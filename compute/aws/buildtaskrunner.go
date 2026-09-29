// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// BuildTaskRunner runs each build as its own ECS task, and is the hosted
// [BuildRunner].
//
// # What this is instead of
//
// Two constructions it replaces, and why neither is acceptable here:
//
//   - [ExecRunner], the builder as a subprocess of apphub. USOSS-41 records why
//     that is refused by type: kaniko unpacks the image into the process tree it
//     runs in, so a Dockerfile RUN instruction reads whatever that process can
//     reach.
//   - A local container runtime, the builder in a sibling container on a daemon
//     apphub drives through its socket. That works, and it needs a host with
//     user-namespace remapping, project-quota-backed overlay2 on XFS and an
//     operator-installed egress firewall — three properties a provider can only
//     *ask a daemon to confirm*, and a fourth (the firewall) it cannot confirm at
//     all. The daemon's labels declared the policy; nothing proved it.
//
// A task is the same isolation argument with the substrate enforcing it. The
// task has its own kernel boundary, its own network interface and its own
// security groups, and none of that is a label this provider took on trust.
//
// # The property everything rests on
//
// **The build task holds no task role.** [Validate] refuses a task definition
// that carries one, because on Fargate every container in a task shares one
// network namespace: the task metadata credentials endpoint is reachable from
// the container running the Dockerfile, so a role attached for any container's
// benefit is a credential repository-authored code can read. There is no
// sidecar arrangement that survives this. The only construction that holds is a
// task with no role at all — which is why the context and the artefact cross on
// a filesystem the substrate mounts, rather than through a signed URL that would
// be exactly such a credential, in exactly that environment.
//
// # Slots
//
// A build must not see another build's context or output. Each slot has its
// own EFS filesystem and task definition, with an access point forcing one
// POSIX owner shared with the worker; its task security group reaches only
// that filesystem's NFS endpoint. An access point on a shared filesystem
// alone would not isolate a compromised task that can select another AP.
type BuildTaskRunner struct {
	cfg   Config
	tasks BuildTaskAPI
	logs  BuildLogAPI

	// contextRoot is SharePath's peer for inputs: the directory every build
	// context must be inside, with symlinks already resolved. Resolved once at
	// construction because the checkout resolves its own base the same way, and
	// comparing a resolved path against an unresolved one is how a containment
	// check passes for the wrong reason.
	contextRoot string

	// leaser decides which build may use which of TaskDefinitions. Acquire
	// blocks: the dispatcher already bounds concurrency, and a build that
	// waited briefly for a slot is a slower deploy, where a build refused for
	// want of one is a failed deploy. See [SlotLeaser] for why this is not a
	// semaphore in this process.
	leaser SlotLeaser

	mu        sync.RWMutex
	validated bool
}

var _ BuildRunner = (*BuildTaskRunner)(nil)

// NewBuildTaskRunner builds a runner over supplied ports.
//
// It contacts nothing: construction checks operator configuration and [Validate]
// checks the substrate. Callers that want the SDK clients built for them use
// [NewSDKBuildTaskRunner]. leaser must be shared by every process that uses
// these slots; see [SlotLeaser].
func NewBuildTaskRunner(cfg Config, contextRoot string, tasks BuildTaskAPI, logs BuildLogAPI, leaser SlotLeaser) (*BuildTaskRunner, error) {
	if cfg.Build == nil || cfg.Build.Task == nil {
		return nil, errors.New("aws: a hosted build needs build.task configuration")
	}
	if tasks == nil || logs == nil {
		return nil, errors.New("aws: a hosted build needs a task and a log client")
	}
	if leaser == nil {
		return nil, errors.New("aws: a hosted build needs a slot leaser shared by every worker")
	}
	t := cfg.Build.Task
	if len(t.SlotSecurityGroups) != len(t.TaskDefinitions) {
		return nil, errors.New("aws: each build slot needs its own network security group")
	}
	seenGroups := make(map[string]bool, len(t.SecurityGroups)+len(t.SlotSecurityGroups))
	for _, group := range t.SecurityGroups {
		seenGroups[group] = true
	}
	for _, group := range t.SlotSecurityGroups {
		if strings.TrimSpace(group) == "" || seenGroups[group] {
			return nil, errors.New("aws: build slots need distinct network security groups, separate from shared groups")
		}
		seenGroups[group] = true
	}
	if !cleanAbsolutePath(contextRoot) {
		return nil, errors.New("aws: the build context root must be an absolute directory")
	}
	resolved, err := filepath.EvalSymlinks(contextRoot)
	if err != nil {
		return nil, errors.New("aws: the build context root must exist")
	}
	r := &BuildTaskRunner{
		cfg:         cfg,
		tasks:       tasks,
		logs:        logs,
		contextRoot: resolved,
		leaser:      leaser,
	}
	if len(t.TaskDefinitions) == 0 {
		return nil, errors.New("aws: a hosted build needs at least one build task definition")
	}
	return r, nil
}

// Validate checks the substrate, and exercises it.
//
// The checks are what the container-backed runner this replaced asked of a
// Docker daemon, asked of a task definition instead — and two of them are
// stronger for it, because a task role and a network mode are facts AWS reports
// about a resource rather than labels an operator wrote on one.
//
// It ends by running a real build: a one-layer image from a context this
// function writes, through the same flags a real build uses. That is deliberate
// over a cheaper probe. A version flag proves the image pulled; it does not
// prove the volume mounted, the slot is writable, the builder can write its
// output where this runner will look for it, or that the network configuration
// lets a task reach ECR at all. Every one of those fails at the first real
// deployment instead, which is the wrong place to find out.
//
// There is no flag to skip it. A skip path in a gate is a bypass.
func (r *BuildTaskRunner) Validate(ctx context.Context) error {
	t := r.cfg.Build.Task
	filesystems := make(map[string]bool, len(t.TaskDefinitions))
	for _, name := range t.TaskDefinitions {
		filesystem, err := r.validateTaskDefinition(ctx, name)
		if err != nil {
			return err
		}
		if filesystems[filesystem] {
			return errors.New("aws: build slots must use distinct filesystems")
		}
		filesystems[filesystem] = true
	}
	if err := r.exercise(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	r.validated = true
	r.mu.Unlock()
	return nil
}

func (r *BuildTaskRunner) validateTaskDefinition(ctx context.Context, name string) (string, error) {
	t := r.cfg.Build.Task
	def, err := r.tasks.DescribeBuildTaskDefinition(ctx, name)
	if err != nil || def == nil {
		return "", errors.New("aws: a configured build task definition could not be read")
	}
	// The one that matters. See the type's doc comment: on Fargate a task role
	// is reachable from every container in the task, so a build task with one
	// hands repository-authored code a credential no arrangement of containers
	// takes back.
	if strings.TrimSpace(def.TaskRoleARN) != "" {
		return "", errors.New("aws: a build task definition must carry no task role; on Fargate the " +
			"task credentials endpoint is reachable from the container running the Dockerfile")
	}
	if def.NetworkMode != "awsvpc" {
		return "", errors.New("aws: a build task definition must use awsvpc, which is what gives the " +
			"task its own interface and therefore its own security groups")
	}
	var container *BuildTaskDefinitionContainer
	for i := range def.Containers {
		if def.Containers[i].Name == t.ContainerName {
			container = &def.Containers[i]
		}
	}
	if container == nil {
		return "", errors.New("aws: a build task definition does not declare the configured container")
	}
	// The same rule the container-backed runner enforced on its builder image,
	// for the same reason: the builder is the process that executes
	// repository-authored code, and "whatever is at that tag today" is not a
	// thing to run it in.
	if !builderImagePinned.MatchString(container.Image) {
		return "", errors.New("aws: a build task definition's builder image must be pinned by digest")
	}
	if def.EphemeralStorageGiB < minBuildEphemeralGiB {
		return "", fmt.Errorf("aws: a build task needs at least %d GiB of ephemeral storage; kaniko "+
			"unpacks every layer of the image it builds into it", minBuildEphemeralGiB)
	}
	var mounted *BuildTaskVolume
	for i := range def.Volumes {
		if def.Volumes[i].FileSystemID != "" {
			if mounted != nil {
				return "", errors.New("aws: a build task must mount exactly one shared filesystem")
			}
			mounted = &def.Volumes[i]
		}
	}
	if mounted == nil {
		return "", errors.New("aws: a build task definition declares no shared filesystem, so its " +
			"output cannot reach the process that pushes it")
	}
	// The task must mount through its configured access point, and each slot
	// must have its own filesystem. An AP root alone is not a hard isolation
	// boundary for code capable of selecting a sibling AP on the same FS.
	if mounted.AccessPointID == "" {
		return "", errors.New("aws: a build task's volume must be mounted through an access point")
	}
	if !mounted.TransitEncryption {
		return "", errors.New("aws: a build task's volume must use transit encryption")
	}
	return mounted.FileSystemID, nil
}

// exercise runs one real build end to end.
//
// It leases whichever slot is free, like any build: a worker that starts while
// another is building must not empty that build's slot to validate its own.
func (r *BuildTaskRunner) exercise(ctx context.Context) (err error) {
	lease, ctx, err := r.acquire(ctx)
	if err != nil {
		return err
	}
	safe := true
	defer func() {
		if safe {
			r.release(lease)
		}
	}()
	slot := lease.Slot()
	if err := lease.Confirm(ctx); err != nil {
		return ErrSlotLeaseLost
	}
	dir, err := r.prepareSlot(slot)
	if err != nil {
		return errors.New("aws: the build share is not writable")
	}
	defer func() {
		if !safe {
			return
		}
		confirmCtx, cancel := context.WithTimeout(context.Background(), buildTaskStopTimeout)
		defer cancel()
		if lease.Confirm(confirmCtx) != nil {
			safe = false
			if err == nil {
				err = ErrSlotLeaseLost
			}
			return
		}
		if clearErr := r.clearSlot(slot); clearErr != nil {
			safe = false
			err = errors.New("aws: a validation build slot could not be cleared")
		}
	}()

	// A one-layer image from a context written here. No network beyond the
	// registry pull the task already needs, and no repository involved.
	// Readable through the task's own access point, which forces the same
	// EFS identity as the worker. A context it cannot read fails validation.
	//
	//nolint:gosec // G306: the share is a dedicated filesystem whose only other reader is the build task, confined to this directory by its own access point.
	if err := os.WriteFile(filepath.Join(dir.context, "marker"), []byte("apphub build validation\n"), 0o644); err != nil {
		return errors.New("aws: the build share is not writable")
	}
	//nolint:gosec // G306: same share, same single reader; see the comment above.
	if err := os.WriteFile(filepath.Join(dir.context, "Dockerfile"), []byte("FROM scratch\nCOPY marker /marker\n"), 0o644); err != nil {
		return errors.New("aws: the build share is not writable")
	}
	t := r.cfg.Build.Task
	args := []string{
		"--context=dir://" + filepath.Join(t.SlotPath, "context"),
		"--dockerfile=Dockerfile",
		"--no-push",
		"--no-push-cache",
		"--cache=false",
		// Never contacted: --no-push means this only names the image inside the
		// tarball, and the builder refuses a --tar-path build that names no
		// destination at all.
		"--destination=" + buildValidationDestination,
		"--tar-path=" + filepath.Join(t.SlotPath, buildSlotOutputDir, buildArtefactName),
		"--digest-file=" + filepath.Join(t.SlotPath, buildSlotOutputDir, "digest"),
	}
	stopped, taskErr := r.runTask(ctx, slot, args, io.Discard)
	if !stopped {
		safe = false
	}
	if taskErr != nil {
		// A task that may still be running keeps its lease, even on failed
		// validation. The caller cannot make its slot available to another.
		return fmt.Errorf("aws: a validation build did not complete; the build task cannot run: %w", taskErr)
	}
	info, err := os.Stat(filepath.Join(dir.output, buildArtefactName))
	if err != nil || info.Size() == 0 {
		return errors.New("aws: a validation build wrote no image where this runner reads one, so " +
			"the shared filesystem is not shared")
	}
	return nil
}

// Run executes one build in its own task, and pushes nothing.
//
// The obligation on [BuildRunner] governs every return below: **the builder's
// output never enters a returned error.** It is repository-authored, the caller
// persists what it is given, and the diagnostic is not lost by the rule — it is
// relocated to cmd.Output, which receives the whole stream.
func (r *BuildTaskRunner) Run(ctx context.Context, cmd BuildCommand) (err error) {
	r.mu.RLock()
	ready := r.validated
	r.mu.RUnlock()
	if !ready {
		return errors.New("aws: the build task runner has not validated its substrate")
	}
	// Every argument and the whole context tree are checked before anything is
	// launched, so a command that escapes its context costs no AWS call and
	// leaves no task behind.
	layout, err := r.layout(cmd)
	if err != nil {
		return err
	}
	t := r.cfg.Build.Task
	ctx, cancel := context.WithTimeout(ctx, t.timeout())
	defer cancel()

	lease, ctx, err := r.acquire(ctx)
	if err != nil {
		return err
	}
	safe := true
	defer func() {
		if safe {
			r.release(lease)
		}
	}()
	// A failed build must leave nothing at the caller's output paths, because
	// the provider decides there is something to push by looking for them.
	defer func() {
		if err != nil {
			_ = os.Remove(layout.tar)
			_ = os.Remove(layout.digest)
		}
	}()
	slot := lease.Slot()

	if err := lease.Confirm(ctx); err != nil {
		return ErrSlotLeaseLost
	}
	dir, err := r.prepareSlot(slot)
	if err != nil {
		return errors.New("aws: the build share could not be prepared")
	}
	// Never clear or release a slot while its task might still be running.
	// Cleanup is independent of cancellation, and a failed cleanup leaves the
	// lease held. A later owner also reconciles ECS before touching the slot.
	defer func() {
		if !safe {
			return
		}
		confirmCtx, cancel := context.WithTimeout(context.Background(), buildTaskStopTimeout)
		defer cancel()
		if lease.Confirm(confirmCtx) != nil {
			safe = false
			if err == nil {
				err = ErrSlotLeaseLost
			}
			return
		}
		if clearErr := r.clearSlot(slot); clearErr != nil {
			safe = false
			err = errors.New("aws: a build slot could not be cleared; operator cleanup is required")
		}
	}()

	if err := r.copyContext(layout.context, dir.context); err != nil {
		return err
	}
	stopped, taskErr := r.runTask(ctx, slot, r.taskArgs(layout), cmd.Output)
	if !stopped {
		safe = false
	}
	if taskErr != nil {
		return taskErr
	}
	// The image about to be read back is trusted only if no other build could
	// have written this slot while this one ran.
	if err := lease.Confirm(ctx); err != nil {
		return ErrSlotLeaseLost
	}
	// The artefact crosses back into the process that will push it, bounded on
	// the way. Keep both the leased slot and its actual out directory pinned:
	// a task-controlled symlink or rename must not redirect either read.
	slotRoot, err := os.OpenRoot(dir.root)
	if err != nil {
		return errors.New("aws: the build slot could not be opened for read-back")
	}
	defer func() { _ = slotRoot.Close() }()
	output, err := openSlotOutput(slotRoot)
	if err != nil {
		return err
	}
	defer func() { _ = output.Close() }()
	// The provider then stats these paths itself before minting a credential;
	// a build that exited zero and wrote nothing mints none.
	if err := copyBounded(output, buildArtefactName, layout.tar, buildTaskDiskBytes); err != nil {
		return err
	}
	if err := copyBounded(output, "digest", layout.digest, buildTaskDigestBytes); err != nil {
		return err
	}
	return nil
}

// taskArgs rewrites the provider's argument list for the task's own filesystem.
//
// Only the three path arguments move. The destinations, the build arguments and
// the three flags that make this a build rather than a publish are passed
// through exactly as composed, so what runs in the task is what
// [imageBuilder.build] asked for.
func (r *BuildTaskRunner) taskArgs(l buildTaskLayout) []string {
	t := r.cfg.Build.Task
	slotContext := filepath.Join(t.SlotPath, "context")
	args := []string{
		"--context=dir://" + slotContext,
		"--dockerfile=" + l.dockerfileRel,
		"--tar-path=" + filepath.Join(t.SlotPath, buildSlotOutputDir, buildArtefactName),
		"--digest-file=" + filepath.Join(t.SlotPath, buildSlotOutputDir, "digest"),
	}
	return append(args, l.passthrough...)
}

// runTask launches, watches and reports one task. The first result is true
// only after ECS reports STOPPED; callers must retain the lease otherwise.
func (r *BuildTaskRunner) runTask(ctx context.Context, slot int, args []string, out io.Writer) (stopped bool, err error) {
	t := r.cfg.Build.Task
	groups := make([]string, 0, len(t.SecurityGroups)+1)
	groups = append(groups, t.SecurityGroups...)
	groups = append(groups, t.SlotSecurityGroups[slot])
	arn, err := r.tasks.RunTask(ctx, BuildTaskRequest{
		Cluster:        t.Cluster,
		TaskDefinition: t.TaskDefinitions[slot],
		ContainerName:  t.ContainerName,
		Command:        args,
		Subnets:        t.Subnets,
		SecurityGroups: groups,
		StartedBy:      buildTaskStartedBy,
	})
	if err != nil || arn == "" {
		// A failed API response does not prove ECS never launched the task.
		// Keep the slot until a subsequent owner can reconcile it.
		return false, errors.New("aws: the build task could not be started")
	}
	defer func() {
		if stopped {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), buildTaskStopTimeout)
		defer cancel()
		if stopErr := r.stopAndWait(cleanupCtx, arn); stopErr != nil {
			err = errors.Join(err, errors.New("aws: the build task could not be confirmed stopped; its slot remains unavailable"))
			return
		}
		stopped = true
	}()

	stream := t.LogStreamPrefix + "/" + t.ContainerName + "/" + taskID(arn)
	token := ""
	ticker := time.NewTicker(t.pollInterval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return false, errors.New("aws: the build task did not finish within its deadline")
		case <-ticker.C:
		}
		token = r.drainLogs(ctx, stream, token, out)
		record, describeErr := r.tasks.DescribeTask(ctx, t.Cluster, arn)
		if describeErr != nil || record == nil {
			continue
		}
		if !record.Stopped() {
			continue
		}
		stopped = true
		// One last read, after the container is gone: awslogs flushes on exit
		// and the most useful lines of a failed build are the last ones.
		r.drainLogs(ctx, stream, token, out)
		return true, r.outcome(*record)
	}
}

// stopAndWait is also used when a new owner discovers an orphaned task.
// A StopTask acknowledgement is not a STOPPED observation: the task may still
// be writing its slot for seconds afterward.
func (r *BuildTaskRunner) stopAndWait(ctx context.Context, arn string) error {
	t := r.cfg.Build.Task
	if err := r.tasks.StopTask(ctx, t.Cluster, arn, "apphub build finished"); err != nil {
		record, describeErr := r.tasks.DescribeTask(ctx, t.Cluster, arn)
		if describeErr != nil || record == nil || !record.Stopped() {
			return errors.New("aws: the build task could not be stopped")
		}
		return nil
	}
	ticker := time.NewTicker(t.pollInterval())
	defer ticker.Stop()
	for {
		record, err := r.tasks.DescribeTask(ctx, t.Cluster, arn)
		if err == nil && record != nil && record.Stopped() {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("aws: the build task did not report STOPPED within the cleanup deadline")
		case <-ticker.C:
		}
	}
}

// outcome decides what a stopped task means. Every refusal is a fixed string:
// the builder's output travelled the log writer, and none of it comes back here.
func (r *BuildTaskRunner) outcome(record BuildTaskRecord) error {
	t := r.cfg.Build.Task
	for _, container := range record.Containers {
		if container.Name != t.ContainerName {
			continue
		}
		switch {
		case container.ExitCode == nil:
			// Never ran, or was killed. Not zero, and treating it as zero is
			// how a task that failed to start reads as a build that succeeded
			// and wrote nothing.
			return errors.New("aws: the build task stopped without running its builder")
		case *container.ExitCode != 0:
			return errors.New("aws: the image build failed")
		default:
			return nil
		}
	}
	return errors.New("aws: the build task reported no builder container")
}

// drainLogs moves whatever the builder has written into the caller's writer and
// returns the token to read from next.
//
// Every failure is silent and returns the token unchanged. A log stream that
// does not exist yet is the normal case for the first few polls — awslogs
// creates it when the container first writes — and a build is not failed for
// want of its own diagnostics.
func (r *BuildTaskRunner) drainLogs(ctx context.Context, stream, token string, out io.Writer) string {
	if out == nil {
		return token
	}
	t := r.cfg.Build.Task
	for {
		events, next, err := r.logs.GetLogEvents(ctx, t.LogGroup, stream, token)
		if err != nil {
			return token
		}
		for _, event := range events {
			_, _ = io.WriteString(out, event.Message+"\n")
		}
		if next == "" || next == token {
			return token
		}
		token = next
		if len(events) == 0 {
			return token
		}
	}
}

// acquire leases a slot and checks ECS before any filesystem operation. A
// previous worker may have died after launching a task; the lease alone says
// nothing about whether that task is still writing this slot.
func (r *BuildTaskRunner) acquire(ctx context.Context) (SlotLease, context.Context, error) {
	lease, err := r.leaser.Acquire(ctx, r.cfg.Build.Task.TaskDefinitions)
	if err != nil {
		return nil, nil, err
	}
	if slot := lease.Slot(); slot < 0 || slot >= len(r.cfg.Build.Task.TaskDefinitions) {
		_ = lease.Release(context.WithoutCancel(ctx))
		return nil, nil, errors.New("aws: the slot leaser returned a slot that is not configured")
	}
	leased, cancel := context.WithCancelCause(ctx)
	go func() {
		select {
		case <-lease.Lost():
			cancel(ErrSlotLeaseLost)
		case <-leased.Done():
		}
	}()
	held := &cancelOnRelease{SlotLease: lease, cancel: func() { cancel(nil) }}
	if err := r.reconcileSlot(leased, held); err != nil {
		// Do not return this slot to the pool on a failed or incomplete ECS
		// check. The leaser keeps renewing until this worker exits.
		cancel(err)
		return nil, nil, err
	}
	return held, leased, nil
}

func (r *BuildTaskRunner) reconcileSlot(ctx context.Context, lease SlotLease) error {
	if err := lease.Confirm(ctx); err != nil {
		return ErrSlotLeaseLost
	}
	t := r.cfg.Build.Task
	tasks, err := r.tasks.ListBuildTasks(ctx, t.Cluster, t.TaskDefinitions[lease.Slot()])
	if err != nil {
		return errors.New("aws: running build tasks could not be listed before slot reuse")
	}
	for _, arn := range tasks {
		if arn == "" {
			return errors.New("aws: a build task could not be identified before slot reuse")
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), buildTaskStopTimeout)
		err := r.stopAndWait(cleanupCtx, arn)
		cancel()
		if err != nil {
			return errors.New("aws: an orphaned build task could not be confirmed stopped")
		}
		if err := lease.Confirm(ctx); err != nil {
			return ErrSlotLeaseLost
		}
	}
	return nil
}

// release gives a proven-stopped, cleared slot back using a context independent
// of a cancelled build.
func (r *BuildTaskRunner) release(lease SlotLease) {
	releaseCtx, cancel := context.WithTimeout(context.Background(), buildTaskStopTimeout)
	defer cancel()
	_ = lease.Release(releaseCtx)
}

// cancelOnRelease ends the lease's watcher when the slot is given back.
type cancelOnRelease struct {
	SlotLease
	cancel func()
}

func (c *cancelOnRelease) Release(ctx context.Context) error {
	c.cancel()
	return c.SlotLease.Release(ctx)
}

// taskID is the trailing segment of a task ARN, which is what awslogs uses as
// the last element of a stream name.
func taskID(arn string) string {
	if index := strings.LastIndex(arn, "/"); index >= 0 {
		return arn[index+1:]
	}
	return arn
}
