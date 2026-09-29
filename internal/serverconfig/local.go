// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package serverconfig

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	localServerFile      = "server.yaml"
	localAWSFile         = "aws.yaml"
	localTransactionFile = "transaction.key"
	localClientSecret    = "client.secret"
	localClientSecretVal = "replace-this-oauth-client-secret"
	localGoogleClientID  = "replace-this-google-client-id"
	localAdminSubject    = "replace-with-your-subject-after-first-login"
	localAccount         = "local-dev-account"
	transactionKeySize   = 32
)

// LocalOptions names the gitignored directory and the local store the skeleton
// should point at. StaticDir must be the built portal directory (or any
// nonempty path serve can use as a fallback while Vite owns the UI).
type LocalOptions struct {
	Dir       string
	StaticDir string
	Endpoint  string
	Region    string
	TableName string
}

// LocalWriteResult reports which skeleton files were created. It never includes
// file contents: the transaction key is random material and the client secret
// placeholder is replaced with a real OAuth secret by the operator.
type LocalWriteResult struct {
	Dir      string
	Config   string
	Created  []string
	Existing []string
}

// WriteLocal writes a loopback serve skeleton that Load accepts. Existing files
// are left alone so a filled-in client secret or edited YAML is not replaced.
//
// The AWS file is only parse-valid: serve reads it to bind target policy, and
// it contains no account-shaped identifiers. It cannot deploy to a real account.
func WriteLocal(opts LocalOptions) (LocalWriteResult, error) {
	if strings.TrimSpace(opts.Dir) == "" || strings.TrimSpace(opts.StaticDir) == "" {
		return LocalWriteResult{}, errors.New("serverconfig: local dir and staticDir are required")
	}
	dir, err := filepath.Abs(opts.Dir)
	if err != nil {
		return LocalWriteResult{}, fmt.Errorf("serverconfig: local dir: %w", err)
	}
	staticDir, err := filepath.Abs(opts.StaticDir)
	if err != nil {
		return LocalWriteResult{}, fmt.Errorf("serverconfig: staticDir: %w", err)
	}
	if opts.Endpoint == "" {
		opts.Endpoint = "http://127.0.0.1:18000"
	}
	if opts.Region == "" {
		opts.Region = "us-east-1"
	}
	if opts.TableName == "" {
		opts.TableName = "apphub-local"
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return LocalWriteResult{}, fmt.Errorf("serverconfig: create local dir: %w", err)
	}

	result := LocalWriteResult{Dir: dir, Config: filepath.Join(dir, localServerFile)}
	writes := []struct {
		name string
		mode os.FileMode
		data func() ([]byte, error)
	}{
		{localAWSFile, 0o600, func() ([]byte, error) { return []byte(localAWSYAML()), nil }},
		{localServerFile, 0o600, func() ([]byte, error) {
			return []byte(localServerYAML(staticDir, opts)), nil
		}},
		{localTransactionFile, 0o600, randomTransactionKey},
		{localClientSecret, 0o600, func() ([]byte, error) { return []byte(localClientSecretVal + "\n"), nil }},
	}
	for _, file := range writes {
		path := filepath.Join(dir, file.name)
		if _, err := os.Stat(path); err == nil {
			result.Existing = append(result.Existing, path)
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return LocalWriteResult{}, fmt.Errorf("serverconfig: stat %s: %w", file.name, err)
		}
		data, err := file.data()
		if err != nil {
			return LocalWriteResult{}, err
		}
		if err := os.WriteFile(path, data, file.mode); err != nil {
			return LocalWriteResult{}, fmt.Errorf("serverconfig: write %s: %w", file.name, err)
		}
		result.Created = append(result.Created, path)
	}
	return result, nil
}

func randomTransactionKey() ([]byte, error) {
	key := make([]byte, transactionKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("serverconfig: generate transaction key: %w", err)
	}
	return key, nil
}

func localServerYAML(staticDir string, opts LocalOptions) string {
	return fmt.Sprintf(`publicOrigin: http://127.0.0.1:5173
listenAddress: 127.0.0.1:8081
staticDir: %s
auth:
  allowLoopbackHTTP: true
  transactionKeyFile: ./%s
  providers:
    - id: google
      label: Google
      kind: google
      clientId: %s
      clientSecretFile: ./%s
      allowedEmails: [developer@example.invalid]
  # No one is an admin until you say so. Log in once as developer@example.invalid,
  # copy the "Subject" value shown at /settings/sessions, and replace it below —
  # then restart serve. providerId must match a configured auth.providers[].id.
  admins:
    - providerId: google
      subject: %s
store:
  region: %s
  tableName: %s
  auditTableName: %s
  endpoint: %s
targets:
  local:
    label: Local development
    awsConfigFile: ./%s
    deployConfig:
      resourcePrefix: apphub-local
      allowedSourceHosts: [github.com]
      placement:
        name: local
      workloadIdentityMode: native
    policy:
      resourceSizes:
        - cpu: 256
          memory: 512
      maxReplicas: 1
      executionModes: [service]
      publicExposure: false
source:
  repositories:
    - url: https://github.com/example/application
      auth: public
`, yamlScalar(staticDir), localTransactionFile, localGoogleClientID, localClientSecret, localAdminSubject, opts.Region, opts.TableName, opts.TableName+"-audit", opts.Endpoint, localAWSFile)
}

func localAWSYAML() string {
	return fmt.Sprintf(`region: us-east-1
placements:
  local:
    clusterArn: arn:aws:ecs:us-east-1:%s:cluster/local
    vpc: vpc-local
    subnets: [subnet-local]
    securityGroups: [sg-local]
identity:
  pathPrefix: /apphub-local/
  namePrefix: apphub-local-
  permissionsBoundary: arn:aws:iam::%s:policy/local-boundary
registry:
  namePrefix: apphub-local/
  immutableTags: false
build:
  executorPath: /kaniko/executor
  pusherPath: /usr/local/bin/crane
  pushRoleArn: arn:aws:iam::%s:role/local-push
  task:
    cluster: arn:aws:ecs:us-east-1:%s:cluster/local
    taskDefinitions: [apphub-local-build-0]
    containerName: builder
    subnets: [subnet-local]
    securityGroups: [sg-local]
    sharePath: /var/lib/apphub/build
    slotPath: /build
    logGroup: /apphub-local/build
    logStreamPrefix: build
container:
  namePrefix: apphub-local-
  executionRolePathPrefix: /apphub-local/execution/
  executionRolePermissionsBoundary: arn:aws:iam::%s:policy/local-boundary
`, localAccount, localAccount, localAccount, localAccount, localAccount)
}

func yamlScalar(value string) string {
	if value == "" || strings.ContainsAny(value, ":#{}[],&*?|>!%%@`'") || strings.ContainsAny(value, " \t\n") {
		return fmt.Sprintf("%q", value)
	}
	return value
}
