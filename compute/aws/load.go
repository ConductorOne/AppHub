// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

const maxConfigBytes = 1 << 20

// LoadConfig reads one strict lower-camel YAML operator configuration. It does
// not discover credentials or contact AWS, so the API may load the same nonsecret
// configuration to bind target readiness to its policy. JSON serialization of
// Config excludes runtime hooks/resolvers and contains no credential material.
// NewFromConfig additionally checks the real isolated runner and AWS credentials.
func LoadConfig(path string) (Config, error) {
	// #nosec G304 -- this is an operator-selected configuration file, never request input;
	// the bounded strict decoder below rejects oversized and unknown content.
	f, err := os.Open(path)
	if err != nil {
		return Config{}, errors.New("aws: cannot open provider configuration")
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil || len(data) > maxConfigBytes {
		return Config{}, errors.New("aws: provider configuration is unreadable or exceeds 1 MiB")
	}
	var cfg Config
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		// Do not echo a malformed document: an operator may have pasted a
		// credential into an unsupported field by mistake.
		return Config{}, errors.New("aws: invalid provider YAML or unknown field")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("aws: exactly one provider YAML document is required")
	}
	if err := validateHostedConfig(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// validateHostedConfig adds the hosted deployment restrictions without changing
// New's general-purpose provider contract (which also serves non-container users).
func validateHostedConfig(cfg Config) error {
	required := func(field, value string) error {
		if value == "" || value != strings.TrimSpace(value) || strings.ContainsAny(value, "\x00\r\n\t") {
			return fmt.Errorf("aws: %s must be explicitly configured without whitespace controls", field)
		}
		return nil
	}
	for _, field := range []struct{ name, value string }{
		{"region", cfg.Region},
		{"identity.pathPrefix", cfg.Identity.PathPrefix},
		{"identity.namePrefix", cfg.Identity.NamePrefix},
		{"identity.permissionsBoundary", cfg.Identity.PermissionsBoundary},
	} {
		if err := required(field.name, field.value); err != nil {
			return err
		}
	}
	if strings.Contains(cfg.Name, ":") {
		return errors.New("aws: provider name cannot contain a colon")
	}
	if len(cfg.Placements) == 0 {
		return errors.New("aws: at least one named placement is required")
	}
	if cfg.DefaultPlacement != "" {
		if _, ok := cfg.Placements[cfg.DefaultPlacement]; !ok {
			return errors.New("aws: defaultPlacement must name a configured placement")
		}
	}
	if cfg.Registry == nil || cfg.Build == nil || cfg.Container == nil {
		return errors.New("aws: hosted source deployments require registry, build and container configuration")
	}
	if cfg.Registry.ImmutableTags {
		return errors.New("aws: registry.immutableTags is incompatible with the deployment module's moving latest tag")
	}
	for _, field := range []struct{ name, value string }{
		{"registry.namePrefix", cfg.Registry.NamePrefix},
		{"build.executorPath", cfg.Build.ExecutorPath},
		{"build.pusherPath", cfg.Build.PusherPath},
		{"build.pushRoleArn", cfg.Build.PushRoleARN},
		{"container.namePrefix", cfg.Container.NamePrefix},
		{"container.executionRolePathPrefix", cfg.Container.ExecutionRolePathPrefix},
		{"container.executionRolePermissionsBoundary", cfg.Container.ExecutionRolePermissionsBoundary},
	} {
		if err := required(field.name, field.value); err != nil {
			return err
		}
	}
	if !filepath.IsAbs(cfg.Build.ExecutorPath) || !filepath.IsAbs(cfg.Build.PusherPath) {
		return errors.New("aws: build executorPath and pusherPath must be absolute")
	}
	if cfg.Build.ExecutorPath == cfg.Build.PusherPath {
		return errors.New("aws: build and push must use separate executables")
	}
	if err := cfg.Build.validateSessionDuration(); err != nil {
		return err
	}
	if err := validateBuildTask(cfg.Build.Task); err != nil {
		return err
	}
	if cfg.Build.MaxContextBytes < 0 || cfg.Build.CacheTTL < 0 || cfg.PollInterval < 0 {
		return errors.New("aws: configured build bounds and polling durations cannot be negative")
	}
	// The hosted configuration has no external resolver injection. Database
	// passwords must be durably published through this provider's SSM store.
	if cfg.Container.Secrets != nil || cfg.IsRetryable != nil {
		return errors.New("aws: hosted configuration cannot contain runtime hooks or external secret resolvers")
	}
	if err := validateTLSTermination(cfg.Container); err != nil {
		return err
	}
	if cfg.Relational != nil && cfg.Secrets == nil {
		return errors.New("aws: relational deployments require explicit secrets configuration for SSM password publication")
	}
	if cfg.Secrets != nil {
		if _, err := newSecretStore(nil, *cfg.Secrets); err != nil {
			return err
		}
	}
	for _, name := range cfg.placementNames() {
		pc := cfg.Placements[name]
		if err := required("placement name", name); err != nil {
			return err
		}
		if pc.Region != "" && pc.Region != cfg.Region {
			return errors.New("aws: every hosted placement must use the provider region; configure another target for another region")
		}
		for _, field := range []struct{ name, value string }{
			{"placement.clusterArn", pc.ClusterARN}, {"placement.vpc", pc.VPC},
		} {
			if err := required(field.name, field.value); err != nil {
				return err
			}
		}
		if len(pc.Subnets) == 0 || len(pc.SecurityGroups) == 0 {
			return errors.New("aws: every hosted placement needs explicit subnets and baseline securityGroups")
		}
		for _, subnet := range pc.Subnets {
			if err := required("placement subnet", subnet); err != nil {
				return err
			}
		}
		for _, group := range pc.SecurityGroups {
			if err := required("placement security group", group); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateBuildTask checks the build task's operator configuration.
//
// It is parse-time only: that every identifier is present and well-shaped. What
// those identifiers actually name -- that the task definitions carry no task
// role, mount an access point, and can run at all -- is
// [BuildTaskRunner.Validate]'s, because it needs the substrate to answer and a
// configuration file cannot.
func validateBuildTask(cfg *BuildTaskConfig) error {
	if cfg == nil {
		return errors.New("aws: hosted builds require build.task; the builder runs in its own " +
			"task, never as a process of this one")
	}
	required := func(field, value string) error {
		if value == "" || value != strings.TrimSpace(value) || strings.ContainsAny(value, "\x00\r\n\t") {
			return fmt.Errorf("aws: build.task.%s must be explicitly configured without whitespace controls", field)
		}
		return nil
	}
	for _, field := range []struct{ name, value string }{
		{"cluster", cfg.Cluster},
		{"containerName", cfg.ContainerName},
		{"logGroup", cfg.LogGroup},
		{"logStreamPrefix", cfg.LogStreamPrefix},
	} {
		if err := required(field.name, field.value); err != nil {
			return err
		}
	}
	// One task definition per concurrent build, because each is bound to the
	// access point that confines that build to its own slot. Zero of them is a
	// provider that cannot build; duplicates would be two builds sharing one
	// slot, which is the confinement failing quietly.
	if len(cfg.TaskDefinitions) == 0 {
		return errors.New("aws: build.task.taskDefinitions needs at least one entry, one per " +
			"concurrent build")
	}
	seen := make(map[string]bool, len(cfg.TaskDefinitions))
	for _, definition := range cfg.TaskDefinitions {
		if err := required("taskDefinitions", definition); err != nil {
			return err
		}
		if seen[definition] {
			return errors.New("aws: build.task.taskDefinitions must not repeat; two builds sharing " +
				"one definition share one slot")
		}
		seen[definition] = true
	}
	if len(cfg.Subnets) == 0 || len(cfg.SecurityGroups) == 0 {
		return errors.New("aws: build.task needs explicit subnets and securityGroups; they are the " +
			"build's network boundary")
	}
	for _, subnet := range cfg.Subnets {
		if err := required("subnets", subnet); err != nil {
			return err
		}
	}
	for _, group := range cfg.SecurityGroups {
		if err := required("securityGroups", group); err != nil {
			return err
		}
	}
	if !cleanAbsolutePath(cfg.SharePath) || !cleanAbsolutePath(cfg.SlotPath) {
		return errors.New("aws: build.task.sharePath and slotPath must be absolute directories")
	}
	if cfg.Timeout < 0 || cfg.PollInterval < 0 {
		return errors.New("aws: build.task timeouts cannot be negative")
	}
	return nil
}

func validateHostedRunner(ctx context.Context, runner BuildRunner) error {
	if runner == nil {
		return errors.New("aws: hosted builds require an isolated container runner")
	}
	v := reflect.ValueOf(runner)
	if (v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface) && v.IsNil() {
		return errors.New("aws: hosted builds require a nonnil isolated container runner")
	}
	switch runner.(type) {
	case ExecRunner, *ExecRunner:
		return errors.New("aws: ExecRunner is forbidden for hosted builds")
	}
	validator, ok := runner.(interface{ Validate(context.Context) error })
	if !ok {
		return errors.New("aws: hosted build runner must validate actual runtime isolation")
	}
	if err := validator.Validate(ctx); err != nil {
		// Which check failed, not merely that one did. Validate's errors name
		// a task definition property or a step of the validation build, and
		// they are the only description of the substrate an operator gets.
		return fmt.Errorf("aws: build runtime isolation validation failed: %w", err)
	}
	return nil
}
