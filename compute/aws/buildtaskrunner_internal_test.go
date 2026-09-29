// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// The build task's substrate, faked at the port rather than at the SDK.
//
// Everything above [Substrate] is the same code against an account and against
// memory, which is what makes a fake here evidence about the real runner and not
// about a parallel implementation. The one thing this fake has to simulate is the
// part a real task does on a filesystem this process cannot see: writing the
// image and the digest into the slot.
type fakeBuildTasks struct {
	mu sync.Mutex

	definitions map[string]*BuildTaskDefinition
	runs        []BuildTaskRequest
	stopped     []string

	// slotDir is the worker-side slot a build lands in, which a real task
	// reaches through its own access point and this fake reaches directly.
	slotDir string

	// onRun stands in for the task. It receives the slot directory the runner
	// prepared and returns the container's exit code.
	onRun func(slot string, in BuildTaskRequest) int

	runErr  error
	listErr error
	stopErr error
	// A delayed StopTask acknowledgement does not mean the task is STOPPED.
	stopDone <-chan struct{}
	stopping bool
	// An orphan belongs to the slot but predates this runner's own RunTask.
	orphan        string
	orphanStopped bool
	running       bool
}

func (f *fakeBuildTasks) ListBuildTasks(_ context.Context, _, _ string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	var tasks []string
	if f.orphan != "" && !f.orphanStopped {
		tasks = append(tasks, f.orphan)
	}
	if f.running && len(f.runs) != 0 {
		tasks = append(tasks, fakeTaskARN)
	}
	return tasks, nil
}

const fakeTaskARN = "arn:aws:ecs:us-west-2:" + MemoryAccount + ":task/test/" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func (f *fakeBuildTasks) RunTask(_ context.Context, in BuildTaskRequest) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.runErr != nil {
		return "", f.runErr
	}
	f.runs = append(f.runs, in)
	return fakeTaskARN, nil
}

func (f *fakeBuildTasks) DescribeTask(ctx context.Context, _, taskARN string) (*BuildTaskRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if taskARN == f.orphan && f.orphan != "" {
		if !f.orphanStopped {
			return &BuildTaskRecord{ARN: taskARN, LastStatus: "RUNNING"}, nil
		}
		return &BuildTaskRecord{ARN: taskARN, LastStatus: "STOPPED"}, nil
	}
	if len(f.runs) == 0 {
		return nil, ErrNoSuchResource
	}
	in := f.runs[len(f.runs)-1]
	if f.stopping && f.stopDone != nil {
		select {
		case <-f.stopDone:
			f.running = false
		default:
		}
	}
	if f.running {
		return &BuildTaskRecord{ARN: taskARN, LastStatus: "RUNNING"}, nil
	}
	code := 0
	if f.onRun != nil {
		code = f.onRun(f.slotDir, in)
	}
	record := &BuildTaskRecord{ARN: taskARN, LastStatus: "STOPPED", StopCode: "EssentialContainerExited"}
	if code < 0 {
		record.Containers = []BuildTaskContainerStatus{{Name: in.ContainerName, Reason: "CannotPullContainerError"}}
		return record, nil
	}
	record.Containers = []BuildTaskContainerStatus{{Name: in.ContainerName, ExitCode: &code}}
	return record, nil
}

func (f *fakeBuildTasks) StopTask(ctx context.Context, _, taskARN, _ string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopped = append(f.stopped, taskARN)
	if f.stopErr != nil {
		return f.stopErr
	}
	if taskARN == f.orphan {
		f.orphanStopped = true
		return nil
	}
	f.stopping = true
	if f.stopDone == nil {
		f.running = false
	}
	return nil
}

func (f *fakeBuildTasks) DescribeBuildTaskDefinition(_ context.Context, name string) (*BuildTaskDefinition, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	def, ok := f.definitions[name]
	if !ok {
		return nil, ErrNoSuchResource
	}
	return def, nil
}

type fakeBuildLogs struct {
	events []BuildLogEvent
	err    error
}

func (f *fakeBuildLogs) GetLogEvents(_ context.Context, _, _, token string) ([]BuildLogEvent, string, error) {
	if f.err != nil {
		return nil, token, f.err
	}
	if token == "done" {
		return nil, "done", nil
	}
	return f.events, "done", nil
}

// soundTaskDefinition is a build task definition with every property
// [BuildTaskRunner.Validate] requires.
func soundTaskDefinition() *BuildTaskDefinition {
	return &BuildTaskDefinition{
		ARN:                 "arn:aws:ecs:us-west-2:" + MemoryAccount + ":task-definition/test-build-0:1",
		TaskRoleARN:         "",
		NetworkMode:         "awsvpc",
		EphemeralStorageGiB: 50,
		Containers: []BuildTaskDefinitionContainer{{
			Name:  "builder",
			Image: "example.invalid/kaniko@sha256:" + strings.Repeat("a", 64),
		}},
		Volumes: []BuildTaskVolume{{
			Name:              "build",
			FileSystemID:      "fs-example",
			AccessPointID:     "fsap-example",
			TransitEncryption: true,
		}},
	}
}

type runnerHarness struct {
	runner  *BuildTaskRunner
	tasks   *fakeBuildTasks
	logs    *fakeBuildLogs
	context string
	output  string
	tar     string
	digest  string
}

// newRunnerHarness wires a validated runner over real directories.
//
// TMPDIR is redirected at a resolved path because the layout check requires the
// provider's private output directory to be a direct, symlink-free child of the
// process temporary directory -- and on some platforms the default one is
// reached through a symlink. Redirecting keeps the production check strict
// rather than loosening it for a test's convenience.
func newRunnerHarness(t *testing.T) *runnerHarness {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolving the temporary directory: %v", err)
	}
	t.Setenv("TMPDIR", base)

	workDir := filepath.Join(base, "work")
	share := filepath.Join(base, "share")
	contextDir := filepath.Join(workDir, "apphub-source-1", "context")
	for _, dir := range []string{workDir, share, filepath.Join(share, "0"), filepath.Join(share, "1"), contextDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(contextDir, "Dockerfile"), []byte("FROM scratch\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	output, err := os.MkdirTemp("", "apphub-build-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(output, 0o700); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		Region: "us-west-2",
		Build: &BuildConfig{
			ExecutorPath: "/kaniko/executor",
			PusherPath:   "/usr/local/bin/crane",
			PushRoleARN:  "arn:aws:iam::" + MemoryAccount + ":role/push",
			Task: &BuildTaskConfig{
				Cluster:            "test",
				TaskDefinitions:    []string{"test-build-0", "test-build-1"},
				ContainerName:      "builder",
				SlotSecurityGroups: []string{"sg-slot-0", "sg-slot-1"},
				Subnets:            []string{"subnet-example"},
				SecurityGroups:     []string{"sg-build"},
				SharePath:          share,
				SlotPath:           "/build",
				LogGroup:           "/test/build",
				LogStreamPrefix:    "build",
				PollInterval:       time.Millisecond,
			},
		},
	}
	second := soundTaskDefinition()
	second.ARN = "arn:aws:ecs:us-west-2:" + MemoryAccount + ":task-definition/test-build-1:1"
	second.Volumes[0].FileSystemID = "fs-example-1"
	second.Volumes[0].AccessPointID = "fsap-example-1"
	tasks := &fakeBuildTasks{definitions: map[string]*BuildTaskDefinition{
		"test-build-0": soundTaskDefinition(),
		"test-build-1": second,
	}}
	logs := &fakeBuildLogs{}
	runner, err := NewBuildTaskRunner(cfg, workDir, tasks, logs, NewProcessSlotLeaser())
	if err != nil {
		t.Fatalf("NewBuildTaskRunner: %v", err)
	}
	runner.validated = true

	h := &runnerHarness{
		runner: runner, tasks: tasks, logs: logs,
		context: contextDir, output: output,
		tar:    filepath.Join(output, buildArtefactName),
		digest: filepath.Join(output, "digest"),
	}
	tasks.slotDir = filepath.Join(share, "0")
	return h
}

func (h *runnerHarness) command() BuildCommand {
	return BuildCommand{
		Executable: "/kaniko/executor",
		Dir:        h.context,
		Args: []string{
			"--context=" + h.context,
			"--dockerfile=Dockerfile",
			"--no-push",
			"--no-push-cache",
			"--cache=false",
			"--destination=example.invalid/app:latest",
			"--tar-path=" + h.tar,
			"--digest-file=" + h.digest,
		},
	}
}

// writeOutputs is what a real build task does: leave an image and a digest in
// the slot for the worker to read back.
func writeOutputs(slot string, image []byte) int {
	out := filepath.Join(slot, buildSlotOutputDir)
	if err := os.MkdirAll(out, 0o755); err != nil {
		return 1
	}
	if err := os.WriteFile(filepath.Join(out, buildArtefactName), image, 0o644); err != nil {
		return 1
	}
	if err := os.WriteFile(filepath.Join(out, "digest"), []byte("sha256:"+strings.Repeat("b", 64)+"\n"), 0o644); err != nil {
		return 1
	}
	return 0
}

func TestBuildTaskRunnerCopiesTheArtefactBackToTheProviderDirectory(t *testing.T) {
	h := newRunnerHarness(t)
	h.tasks.onRun = func(slot string, _ BuildTaskRequest) int {
		return writeOutputs(slot, []byte("image-bytes"))
	}
	var out bytes.Buffer
	cmd := h.command()
	cmd.Output = &out
	if err := h.runner.Run(context.Background(), cmd); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// The provider stats exactly these two paths before it mints a credential.
	data, err := os.ReadFile(h.tar)
	if err != nil || string(data) != "image-bytes" {
		t.Fatalf("the artefact did not cross back: %v %q", err, data)
	}
	if _, err := os.Stat(h.digest); err != nil {
		t.Fatalf("the digest did not cross back: %v", err)
	}
	// Cleanup leaves the EFS mountpoint in place and empties its contents.
	entries, err := os.ReadDir(filepath.Join(h.runner.cfg.Build.Task.SharePath, "0"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("the mounted slot was not cleared after the build: %v %v", entries, err)
	}
}

// A task can replace out with a pointer to a different worker-mounted slot.
// Even valid artefacts there must not be promoted to private provider output.
func TestBuildTaskRunnerRejectsOutputDirectorySymlinkToSiblingSlot(t *testing.T) {
	h := newRunnerHarness(t)
	h.tasks.onRun = func(slot string, _ BuildTaskRequest) int {
		sibling := filepath.Join(filepath.Dir(slot), "1")
		if writeOutputs(sibling, []byte("sibling-image")) != 0 {
			t.Error("could not write the sibling slot's image and digest")
			return 1
		}
		out := filepath.Join(slot, buildSlotOutputDir)
		if err := os.Remove(out); err != nil {
			t.Error(err)
			return 1
		}
		if err := os.Symlink(filepath.Join("..", "1", buildSlotOutputDir), out); err != nil {
			t.Error(err)
			return 1
		}
		return 0
	}
	if err := h.runner.Run(context.Background(), h.command()); err == nil {
		t.Fatal("a symlink to a sibling build's output was accepted")
	}
	for _, path := range []string{h.tar, h.digest} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the refused build left private output %q: %v", path, err)
		}
	}
}

func TestBuildTaskRunnerRejectsOutputFileSymlink(t *testing.T) {
	h := newRunnerHarness(t)
	h.tasks.onRun = func(slot string, _ BuildTaskRequest) int {
		if writeOutputs(slot, []byte("real-image")) != 0 {
			return 1
		}
		image := filepath.Join(slot, buildSlotOutputDir, buildArtefactName)
		if err := os.Remove(image); err != nil {
			t.Error(err)
			return 1
		}
		if err := os.Symlink(filepath.Join("..", "context", "Dockerfile"), image); err != nil {
			t.Error(err)
			return 1
		}
		return 0
	}
	if err := h.runner.Run(context.Background(), h.command()); err == nil {
		t.Fatal("a symlink at the image path was accepted")
	}
	for _, path := range []string{h.tar, h.digest} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the refused build left private output %q: %v", path, err)
		}
	}
}

func TestBuildTaskRunnerSendsOnlyRewrittenPathsToTheTask(t *testing.T) {
	h := newRunnerHarness(t)
	h.tasks.onRun = func(slot string, _ BuildTaskRequest) int {
		return writeOutputs(slot, []byte("image-bytes"))
	}
	if err := h.runner.Run(context.Background(), h.command()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(h.tasks.runs) != 1 {
		t.Fatalf("expected one task, got %d", len(h.tasks.runs))
	}
	got := strings.Join(h.tasks.runs[0].Command, " ")
	// The three path arguments are rewritten onto the task's own filesystem;
	// nothing tells the task where the worker keeps anything.
	for _, want := range []string{
		"--context=dir:///build/context",
		"--tar-path=/build/out/image.tar",
		"--digest-file=/build/out/digest",
		"--destination=example.invalid/app:latest",
		"--no-push",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the task command is missing %q: %s", want, got)
		}
	}
	if strings.Contains(got, "/kaniko/executor") {
		t.Errorf("the task command must be flags only; ENTRYPOINT is /kaniko/executor: %s", got)
	}
	if strings.Contains(got, h.output) || strings.Contains(got, h.context) {
		t.Errorf("the task command leaked a worker path: %s", got)
	}
	groups := h.tasks.runs[0].SecurityGroups
	if len(groups) != 2 || groups[0] != "sg-build" || groups[1] != "sg-slot-0" {
		t.Errorf("task must reach only its own slot's NFS endpoint: %v", groups)
	}
}

func TestBuildTaskRunnerRefusesSharedSlotNetworkGroups(t *testing.T) {
	for name, groups := range map[string][]string{
		"missing":      nil,
		"wrong count":  {"sg-slot-0"},
		"shared slot":  {"sg-slot-0", "sg-slot-0"},
		"common group": {"sg-build", "sg-slot-1"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newRunnerHarness(t)
			h.runner.cfg.Build.Task.SlotSecurityGroups = groups
			if _, err := NewBuildTaskRunner(h.runner.cfg, h.runner.contextRoot, h.tasks, h.logs, NewProcessSlotLeaser()); err == nil {
				t.Fatal("an unsafe slot network boundary was accepted")
			}
		})
	}
}

// A build that failed must leave nothing where the provider looks for something
// to push. A stale artefact from an earlier attempt would be published as if it
// were this one's.
func TestBuildTaskRunnerLeavesNoArtefactWhenTheBuildFails(t *testing.T) {
	for name, code := range map[string]int{"non-zero exit": 2, "never ran": -1} {
		t.Run(name, func(t *testing.T) {
			h := newRunnerHarness(t)
			h.tasks.onRun = func(slot string, _ BuildTaskRequest) int {
				writeOutputs(slot, []byte("image-bytes"))
				return code
			}
			if err := h.runner.Run(context.Background(), h.command()); err == nil {
				t.Fatal("a failed build was reported as successful")
			}
			for _, path := range []string{h.tar, h.digest} {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("%s survived a failed build", filepath.Base(path))
				}
			}
		})
	}
}

// The obligation on BuildRunner: the builder's output is repository-authored, it
// reaches the caller's log writer, and it never reaches a returned error.
func TestBuildTaskRunnerKeepsBuilderOutputOutOfItsError(t *testing.T) {
	const marker = "canary-from-a-run-instruction"
	h := newRunnerHarness(t)
	h.logs.events = []BuildLogEvent{{Timestamp: time.Now(), Message: marker}}
	h.tasks.onRun = func(string, BuildTaskRequest) int { return 3 }

	var out bytes.Buffer
	cmd := h.command()
	cmd.Output = &out
	err := h.runner.Run(context.Background(), cmd)
	if err == nil {
		t.Fatal("a failed build was reported as successful")
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatalf("builder output reached the returned error: %v", err)
	}
	if !strings.Contains(out.String(), marker) {
		t.Fatalf("builder output did not reach the log writer: %q", out.String())
	}
}

// Every refusal below is decided from the command alone, so a caller that asks
// for something outside its context costs no AWS call and leaves no task behind.
func TestBuildTaskRunnerRefusesBadCommandsBeforeReachingTheSubstrate(t *testing.T) {
	cases := map[string]func(*runnerHarness, *BuildCommand){
		"another executable": func(_ *runnerHarness, c *BuildCommand) { c.Executable = "/bin/sh" },
		"context outside the work directory": func(_ *runnerHarness, c *BuildCommand) {
			c.Dir = os.TempDir()
			c.Args[0] = "--context=" + os.TempDir()
		},
		"unknown argument": func(_ *runnerHarness, c *BuildCommand) {
			c.Args = append(c.Args, "--force-build-metadata")
		},
		"pushing": func(_ *runnerHarness, c *BuildCommand) {
			c.Args[2] = "--no-push=false"
		},
		"cache enabled": func(_ *runnerHarness, c *BuildCommand) {
			c.Args[4] = "--cache=true"
		},
		"output outside the provider directory": func(h *runnerHarness, c *BuildCommand) {
			c.Args[6] = "--tar-path=" + filepath.Join(h.context, buildArtefactName)
		},
		"dockerfile outside the context": func(_ *runnerHarness, c *BuildCommand) {
			c.Args[1] = "--dockerfile=../Dockerfile"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			h := newRunnerHarness(t)
			cmd := h.command()
			mutate(h, &cmd)
			if err := h.runner.Run(context.Background(), cmd); err == nil {
				t.Fatal("an unsafe build command was accepted")
			}
			if len(h.tasks.runs) != 0 {
				t.Fatalf("the substrate was reached for a command that should have been refused")
			}
		})
	}
}

func TestBuildTaskRunnerRefusesBeforeItHasValidated(t *testing.T) {
	h := newRunnerHarness(t)
	h.runner.validated = false
	if err := h.runner.Run(context.Background(), h.command()); err == nil {
		t.Fatal("a build ran against a substrate that was never validated")
	}
}

// Validate is where a task definition's isolation is checked, and the task role
// is the one that matters: on Fargate it is reachable from the container running
// the Dockerfile, so a build task carrying one hands repository-authored code a
// credential.
func TestValidateRefusesABuildTaskThatIsNotIsolated(t *testing.T) {
	cases := map[string]func(*BuildTaskDefinition){
		"a task role": func(d *BuildTaskDefinition) {
			d.TaskRoleARN = "arn:aws:iam::" + MemoryAccount + ":role/anything"
		},
		"bridge networking": func(d *BuildTaskDefinition) { d.NetworkMode = "bridge" },
		"a floating builder image": func(d *BuildTaskDefinition) {
			d.Containers[0].Image = "example.invalid/kaniko:latest"
		},
		"no shared filesystem": func(d *BuildTaskDefinition) { d.Volumes = nil },
		"the file system root": func(d *BuildTaskDefinition) { d.Volumes[0].AccessPointID = "" },
		"another shared filesystem": func(d *BuildTaskDefinition) {
			d.Volumes = append(d.Volumes, BuildTaskVolume{FileSystemID: "fs-extra", AccessPointID: "fsap-extra", TransitEncryption: true})
		},
		"an unencrypted mount":     func(d *BuildTaskDefinition) { d.Volumes[0].TransitEncryption = false },
		"too little scratch space": func(d *BuildTaskDefinition) { d.EphemeralStorageGiB = 20 },
		"a different container":    func(d *BuildTaskDefinition) { d.Containers[0].Name = "other" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			h := newRunnerHarness(t)
			definition := soundTaskDefinition()
			mutate(definition)
			h.tasks.definitions["test-build-0"] = definition
			if err := h.runner.Validate(context.Background()); err == nil {
				t.Fatal("an unisolated build task definition was accepted")
			}
		})
	}
}

func TestValidateRefusesSharedFilesystemAcrossSlots(t *testing.T) {
	h := newRunnerHarness(t)
	h.tasks.definitions["test-build-1"].Volumes[0].FileSystemID = "fs-example"
	if err := h.runner.Validate(context.Background()); err == nil {
		t.Fatal("two slots on one EFS filesystem are not isolated against a task selecting the other's access point")
	}
	if len(h.tasks.runs) != 0 {
		t.Fatal("validation exercised an unisolated task definition")
	}
}

// And the anti-vacuity half: a sound definition passes, through the same code,
// including the exercise build that proves the share really is shared.
func TestValidateAcceptsASoundBuildTaskAndExercisesIt(t *testing.T) {
	h := newRunnerHarness(t)
	h.tasks.onRun = func(slot string, _ BuildTaskRequest) int {
		return writeOutputs(slot, []byte("validation-image"))
	}
	if err := h.runner.Validate(context.Background()); err != nil {
		t.Fatalf("a sound build task was refused: %v", err)
	}
	if len(h.tasks.runs) != 1 {
		t.Fatalf("Validate did not exercise the substrate: %d tasks", len(h.tasks.runs))
	}
	if !h.runner.validated {
		t.Fatal("Validate did not mark the runner ready")
	}
}

// A validation build that leaves nothing behind means the worker and the task
// are not looking at the same filesystem, which is the failure that would
// otherwise surface as every deployment failing to push.
func TestValidateRefusesAShareThatIsNotShared(t *testing.T) {
	h := newRunnerHarness(t)
	h.tasks.onRun = func(string, BuildTaskRequest) int { return 0 }
	if err := h.runner.Validate(context.Background()); err == nil {
		t.Fatal("a share that produced no artefact was accepted")
	}
}

func TestBuildTaskRunnerRejectsNestedOutputParentSymlink(t *testing.T) {
	h := newRunnerHarness(t)
	source, err := os.OpenRoot(h.runner.slotPaths(0).root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = source.Close() }()
	sibling := filepath.Join(filepath.Dir(h.runner.slotPaths(0).root), "1")
	if writeOutputs(sibling, []byte("sibling-image")) != 0 {
		t.Fatal("could not write the sibling slot's image and digest")
	}
	if err := os.Symlink(filepath.Join("..", "1", buildSlotOutputDir), filepath.Join(h.runner.slotPaths(0).root, "nested")); err != nil {
		t.Fatal(err)
	}
	if err := copyBounded(source, filepath.Join("nested", buildArtefactName), h.tar, buildTaskDiskBytes); err == nil {
		t.Fatal("a nested output parent was accepted")
	}
	if _, err := os.Lstat(h.tar); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the refused nested output left a private artefact: %v", err)
	}
}

// The artefact crosses a boundary this process does not control -- the builder
// writes it -- so the read back is bounded rather than trusted.
func TestBuildTaskRunnerBoundsTheArtefactItReadsBack(t *testing.T) {
	h := newRunnerHarness(t)
	source, err := os.OpenRoot(h.output)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = source.Close() }()
	if err := os.WriteFile(filepath.Join(h.output, "oversized"), bytes.Repeat([]byte("x"), 64), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyBounded(source, "oversized", filepath.Join(h.output, "too-big"), 8); err == nil {
		t.Fatal("an output larger than its bound was copied")
	}
	if _, err := os.Lstat(filepath.Join(h.output, "too-big")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a refused copy left a partial file behind")
	}
	// Anti-vacuity: the same call succeeds inside the bound, so the refusal
	// above is the bound and not a broken path.
	if err := copyBounded(source, "oversized", filepath.Join(h.output, "within"), 64); err != nil {
		t.Fatalf("an output inside its bound was refused: %v", err)
	}
}

// Cancellation asks ECS to stop the task and does not release its slot until
// DescribeTask reports STOPPED, regardless of the StopTask acknowledgement.
func TestBuildTaskRunnerWaitsForStoppedBeforeReusingSlot(t *testing.T) {
	h := newRunnerHarness(t)
	h.runner.cfg.Build.Task.TaskDefinitions = h.runner.cfg.Build.Task.TaskDefinitions[:1]
	h.runner.cfg.Build.Task.SlotSecurityGroups = h.runner.cfg.Build.Task.SlotSecurityGroups[:1]
	doneStopping := make(chan struct{})
	h.tasks.running = true
	h.tasks.stopDone = doneStopping
	h.tasks.onRun = func(slot string, _ BuildTaskRequest) int {
		return writeOutputs(slot, []byte("next-build"))
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := make(chan error, 1)
	go func() { first <- h.runner.Run(ctx, h.command()) }()
	waitForBuildTask(t, h.tasks, 1)
	cancel()
	waitForStopRequest(t, h.tasks)
	select {
	case <-first:
		t.Fatal("the build returned before ECS reported STOPPED")
	default:
	}
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer waitCancel()
	if err := h.runner.Run(waitCtx, h.command()); err == nil {
		t.Fatal("a second build was allowed into the still-running slot")
	}
	h.tasks.mu.Lock()
	runs := len(h.tasks.runs)
	h.tasks.mu.Unlock()
	if runs != 1 {
		t.Fatalf("the slot was reused while its first task still ran: %d launches", runs)
	}
	if _, err := os.Stat(filepath.Join(h.runner.slotPaths(0).context, "Dockerfile")); err != nil {
		t.Fatalf("the task's context was cleared before STOPPED: %v", err)
	}
	close(doneStopping)
	select {
	case err := <-first:
		if err == nil {
			t.Fatal("the cancelled build reported success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the build did not return after STOPPED")
	}
	if err := h.runner.Run(context.Background(), h.command()); err != nil {
		t.Fatalf("a confirmed-stopped task did not release its slot: %v", err)
	}
	h.tasks.mu.Lock()
	runs = len(h.tasks.runs)
	h.tasks.mu.Unlock()
	if runs != 2 {
		t.Fatalf("the slot was not reused after STOPPED: %d launches", runs)
	}
}

func waitForBuildTask(t *testing.T, tasks *fakeBuildTasks, count int) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		tasks.mu.Lock()
		started := len(tasks.runs) >= count
		tasks.mu.Unlock()
		if started {
			return
		}
		select {
		case <-deadline:
			t.Fatal("the task did not start")
		case <-time.After(time.Millisecond):
		}
	}
}

func waitForStopRequest(t *testing.T, tasks *fakeBuildTasks) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		tasks.mu.Lock()
		requested := len(tasks.stopped) != 0
		tasks.mu.Unlock()
		if requested {
			return
		}
		select {
		case <-deadline:
			t.Fatal("the task was not asked to stop")
		case <-time.After(time.Millisecond):
		}
	}
}

func TestBuildTaskRunnerRetainsSlotAfterFailedStop(t *testing.T) {
	h := newRunnerHarness(t)
	h.runner.cfg.Build.Task.TaskDefinitions = h.runner.cfg.Build.Task.TaskDefinitions[:1]
	h.runner.cfg.Build.Task.SlotSecurityGroups = h.runner.cfg.Build.Task.SlotSecurityGroups[:1]
	h.tasks.running = true
	h.tasks.stopErr = errors.New("ECS denied StopTask")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.runner.Run(ctx, h.command()) }()
	waitForBuildTask(t, h.tasks, 1)
	cancel()
	if err := <-done; err == nil || !strings.Contains(err.Error(), "slot remains unavailable") {
		t.Fatalf("Run = %v, expected failed cleanup", err)
	}
	waitCtx, stop := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer stop()
	if err := h.runner.Run(waitCtx, h.command()); err == nil {
		t.Fatal("a failed StopTask returned its slot to the pool")
	}
	h.tasks.mu.Lock()
	defer h.tasks.mu.Unlock()
	if len(h.tasks.runs) != 1 {
		t.Fatalf("a new task was launched while the failed stop left its task running: %d", len(h.tasks.runs))
	}
}

func TestBuildTaskRunnerReconcilesOrphanBeforeClearingSlot(t *testing.T) {
	h := newRunnerHarness(t)
	h.tasks.orphan = "arn:aws:ecs:us-west-2:" + MemoryAccount + ":task/test/" + strings.Repeat("b", 32)
	slot := h.runner.slotPaths(0)
	if err := os.MkdirAll(slot.context, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(slot.context, "previous-build"), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.tasks.onRun = func(slot string, _ BuildTaskRequest) int {
		if _, err := os.Lstat(filepath.Join(slot, "context", "previous-build")); !errors.Is(err, os.ErrNotExist) {
			return 1
		}
		return writeOutputs(slot, []byte("fresh"))
	}
	if err := h.runner.Run(context.Background(), h.command()); err != nil {
		t.Fatalf("the orphan was not stopped before slot reuse: %v", err)
	}
	h.tasks.mu.Lock()
	defer h.tasks.mu.Unlock()
	if !h.tasks.orphanStopped {
		t.Fatal("the previous task survived slot reuse")
	}
}

func TestBuildTaskRunnerRefusesSlotWhenTasksCannotBeListed(t *testing.T) {
	h := newRunnerHarness(t)
	h.tasks.listErr = errors.New("ECS unavailable")
	if err := h.runner.Run(context.Background(), h.command()); err == nil {
		t.Fatal("a slot was reused without checking ECS for orphaned tasks")
	}
	if len(h.tasks.runs) != 0 {
		t.Fatal("a task launched despite an unconfirmed slot")
	}
}

func TestBuildTaskRunnerRefusesMissingSlotMount(t *testing.T) {
	h := newRunnerHarness(t)
	mount := h.runner.slotPaths(0).root
	if err := os.Remove(mount); err != nil {
		t.Fatal(err)
	}
	if err := h.runner.Run(context.Background(), h.command()); err == nil {
		t.Fatal("a missing EFS slot mount was silently replaced by a local directory")
	}
	if _, err := os.Lstat(mount); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a replacement slot directory was created: %v", err)
	}
	if len(h.tasks.runs) != 0 {
		t.Fatal("a build was launched without its mounted EFS slot")
	}
}

// A substrate that refuses to launch is a failed build, not a wait to the
// deadline.
func TestBuildTaskRunnerReportsATaskThatCouldNotStart(t *testing.T) {
	h := newRunnerHarness(t)
	h.tasks.runErr = errors.New("capacity is unavailable")
	if err := h.runner.Run(context.Background(), h.command()); err == nil {
		t.Fatal("a build whose task never started was reported as successful")
	}
}

// scriptedLeaser hands out slot zero on a lease whose confirmations follow a
// script, so a test can take the lease away at a chosen step.
type scriptedLeaser struct{ lease *scriptedLease }

func (s *scriptedLeaser) Acquire(context.Context, []string) (SlotLease, error) { return s.lease, nil }

type scriptedLease struct {
	mu       sync.Mutex
	confirms int
	// failFrom is the first confirmation that fails; zero never fails.
	failFrom int
	lost     chan struct{}
	released bool
}

func (l *scriptedLease) Slot() int             { return 0 }
func (l *scriptedLease) Lost() <-chan struct{} { return l.lost }
func (l *scriptedLease) Confirm(context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.confirms++
	if l.failFrom != 0 && l.confirms >= l.failFrom {
		return errors.New("taken over")
	}
	return nil
}
func (l *scriptedLease) Release(context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.released = true
	return nil
}

func TestBuildTaskRunnerTrustsNoImageFromASlotItLost(t *testing.T) {
	h := newRunnerHarness(t)
	// Reconciliation and preparation confirmations hold; the readback
	// confirmation fails after the task completed.
	lease := &scriptedLease{failFrom: 3, lost: make(chan struct{})}
	h.runner.leaser = &scriptedLeaser{lease: lease}
	h.tasks.onRun = func(slot string, _ BuildTaskRequest) int {
		return writeOutputs(slot, []byte("somebody-elses-image"))
	}
	err := h.runner.Run(context.Background(), h.command())
	if !errors.Is(err, ErrSlotLeaseLost) {
		t.Fatalf("Run = %v, want ErrSlotLeaseLost", err)
	}
	if _, err := os.Stat(h.tar); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("an image was read back from a slot this build no longer held")
	}
	if _, err := os.Stat(filepath.Join(h.runner.cfg.Build.Task.SharePath, "0", buildSlotOutputDir)); err != nil {
		t.Fatal("the runner emptied a slot that now belongs to another build")
	}
	if lease.released {
		t.Fatal("the lost lease was released before the slot was cleared")
	}
}

func TestBuildTaskRunnerStopsTheTaskWhenItsLeaseIsLost(t *testing.T) {
	h := newRunnerHarness(t)
	lease := &scriptedLease{lost: make(chan struct{})}
	h.runner.leaser = &scriptedLeaser{lease: lease}
	// The task never finishes on its own; losing the lease is what ends it.
	h.tasks.running = true
	go func() {
		for {
			h.tasks.mu.Lock()
			started := len(h.tasks.runs) > 0
			h.tasks.mu.Unlock()
			if started {
				close(lease.lost)
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	done := make(chan error, 1)
	go func() { done <- h.runner.Run(context.Background(), h.command()) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a build whose lease was lost reported success")
		}
		if _, statErr := os.Stat(h.tar); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatal("a build whose lease was lost produced an image")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("losing the lease did not stop the build")
	}
	if len(h.tasks.stopped) == 0 {
		t.Fatal("the build task was left running in a slot this worker lost")
	}
}

// A compromised builder can revoke every permission bit on directories it
// owns. Both EFS access points enforce the same POSIX identity, so the worker
// can restore traversal and remove the whole tree before the next build.
func TestBuildTaskRunnerClearsOwnerLockedDownOutput(t *testing.T) {
	if share := os.Getenv("APPHUB_OWNER_SLOT_HELPER"); share != "" {
		r := &BuildTaskRunner{cfg: Config{Build: &BuildConfig{Task: &BuildTaskConfig{SharePath: share}}}}
		if _, err := r.prepareSlot(0); err != nil {
			t.Fatalf("unprivileged owner could not recover locked output: %v", err)
		}
		return
	}
	h := newRunnerHarness(t)
	slot := h.runner.slotPaths(0)
	nested := filepath.Join(slot.output, "locked", "deeper")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "payload"), []byte("previous build"), 0o000); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(h.output, "outside")
	if err := os.Mkdir(victim, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(slot.output, "link")); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{nested, filepath.Dir(nested), slot.output} {
		if err := os.Chmod(dir, 0o000); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		// Make t.TempDir cleanup possible if the assertion fails.
		for _, dir := range []string{slot.output, filepath.Dir(nested), nested} {
			_ = os.Chmod(dir, 0o700)
		}
	})
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		// Root could remove a 000 directory without restoring permissions.
		// Run the real cleanup as the access points' effective UID instead.
		for _, path := range []string{slot.root, slot.output, filepath.Dir(nested), nested} {
			if err := os.Chown(path, 65532, 65532); err != nil {
				t.Fatal(err)
			}
		}
		for _, path := range []string{filepath.Dir(slot.root), filepath.Dir(filepath.Dir(slot.root)), filepath.Dir(filepath.Dir(filepath.Dir(slot.root)))} {
			if err := os.Chmod(path, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		cmd := exec.Command("/proc/self/exe", "-test.run=^TestBuildTaskRunnerClearsOwnerLockedDownOutput$")
		cmd.Env = append(os.Environ(), "APPHUB_OWNER_SLOT_HELPER="+filepath.Dir(slot.root))
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65532, Gid: 65532}}
		if result, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("unprivileged slot cleanup failed: %v\n%s", err, result)
		}
	} else if _, err := h.runner.prepareSlot(0); err != nil {
		t.Fatalf("the next build could not recover its owner-owned slot: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(nested, "payload")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("previous build's output survived cleanup: %v", err)
	}
	info, err := os.Stat(victim)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("slot symlink changed an outside directory: %v %v", info, err)
	}
	if err := os.WriteFile(filepath.Join(slot.output, "new"), []byte("new build"), 0o600); err != nil {
		t.Fatalf("the recovered slot was not writable: %v", err)
	}
}

// A legacy root-owned directory is not recoverable by the unprivileged
// worker. This must fail closed rather than pretending the slot was emptied.
// Production prevents this state by forcing UID 65532 at both EFS access
// points; the companion test above proves owner-owned chmod 000 is recoverable.
func TestBuildTaskRunnerRootOwnedOutputFailsClosed(t *testing.T) {
	if share := os.Getenv("APPHUB_DENIED_SLOT_HELPER"); share != "" {
		r := &BuildTaskRunner{cfg: Config{Build: &BuildConfig{Task: &BuildTaskConfig{SharePath: share}}}}
		if err := r.clearSlot(0); err == nil {
			t.Fatal("a non-root worker claimed to clear a root-owned locked directory")
		}
		return
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("constructing a root-owned directory and dropping the helper's UID needs Linux root")
	}
	base, err := os.MkdirTemp("", "apphub-root-owned-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(filepath.Join(base, "share", "0", "out", "locked"), 0o700)
		_ = os.RemoveAll(base)
	})
	share := filepath.Join(base, "share")
	slot := filepath.Join(share, "0")
	locked := filepath.Join(slot, "out", "locked")
	if err := os.MkdirAll(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{base, share} {
		if err := os.Chmod(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chown(slot, 65532, 65532); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/proc/self/exe", "-test.run=^TestBuildTaskRunnerRootOwnedOutputFailsClosed$")
	cmd.Env = append(os.Environ(), "APPHUB_DENIED_SLOT_HELPER="+share)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65532, Gid: 65532}}
	if result, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("non-root cleanup did not fail closed: %v\n%s", err, result)
	}
	if _, err := os.Lstat(locked); err != nil {
		t.Fatalf("the inaccessible tree was reported cleared: %v", err)
	}
}
