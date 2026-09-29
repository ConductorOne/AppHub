// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"reflect"
	"testing"
)

func tree(files map[string]string) Tree {
	t := Tree{Files: make(map[string][]byte, len(files))}
	for name, content := range files {
		t.Files[name] = []byte(content)
	}
	return t
}

func TestFromTreeEmpty(t *testing.T) {
	if res := FromTree(Tree{}); !reflect.DeepEqual(res, Result{}) {
		t.Fatalf("empty tree: got %+v, want zero value", res)
	}
}

func TestFromTreeRootDockerfileWins(t *testing.T) {
	res := FromTree(tree(map[string]string{
		"Dockerfile":         "FROM node:20\nEXPOSE 3000\n",
		"api/Dockerfile":     "FROM golang:1\nEXPOSE 9090\n",
		"Dockerfile.staging": "FROM node:20\nEXPOSE 4000\n",
	}))
	if res.DockerfilePath != "Dockerfile" {
		t.Fatalf("DockerfilePath = %q, want %q", res.DockerfilePath, "Dockerfile")
	}
	if res.SuggestedPort != 3000 {
		t.Fatalf("SuggestedPort = %d, want 3000", res.SuggestedPort)
	}
	if len(res.DockerfileCandidates) != 3 || res.DockerfileCandidates[0] != "Dockerfile" {
		t.Fatalf("DockerfileCandidates = %v", res.DockerfileCandidates)
	}
	if res.DockerfilePorts["api/Dockerfile"] != 9090 {
		t.Fatalf("nested candidate port = %d, want 9090", res.DockerfilePorts["api/Dockerfile"])
	}
}

func TestFromTreeShallowestNonRootCandidateWins(t *testing.T) {
	res := FromTree(tree(map[string]string{
		"deep/nested/Dockerfile": "FROM node:20\n",
		"api/Dockerfile":         "FROM node:20\nEXPOSE 8080\n",
	}))
	if res.DockerfilePath != "api/Dockerfile" {
		t.Fatalf("DockerfilePath = %q, want %q", res.DockerfilePath, "api/Dockerfile")
	}
}

func TestParseExposePortIgnoresCommentsAndVariables(t *testing.T) {
	res := FromTree(tree(map[string]string{
		"Dockerfile": "FROM node:20\n# EXPOSE 1234\nEXPOSE ${PORT}\nEXPOSE 5000/tcp\n",
	}))
	if res.SuggestedPort != 5000 {
		t.Fatalf("SuggestedPort = %d, want 5000", res.SuggestedPort)
	}
}

func TestFromTreeNoDockerfile(t *testing.T) {
	res := FromTree(tree(map[string]string{"README.md": "hello"}))
	if res.DockerfilePath != "" || res.SuggestedPort != 0 || res.DockerfileCandidates != nil {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestComposePreviewShortAndLongPorts(t *testing.T) {
	compose := `
services:
  web:
    build: .
    ports:
      - "8080:80"
  worker:
    image: myorg/worker:latest
  db:
    image: postgres:16
    ports:
      - target: 5432
        published: 5432
`
	res := FromTree(tree(map[string]string{
		"Dockerfile":         "FROM node:20\n",
		"docker-compose.yml": compose,
	}))
	if res.ComposePreview == nil {
		t.Fatal("expected a compose preview")
	}
	if res.ComposePreview.Path != "docker-compose.yml" {
		t.Fatalf("Path = %q", res.ComposePreview.Path)
	}
	byName := map[string]ComposeService{}
	for _, svc := range res.ComposePreview.Services {
		byName[svc.Name] = svc
	}
	if !byName["web"].HasBuild || byName["web"].Port != 80 {
		t.Fatalf("web service = %+v", byName["web"])
	}
	if byName["worker"].Image != "myorg/worker:latest" || byName["worker"].HasBuild {
		t.Fatalf("worker service = %+v", byName["worker"])
	}
	if byName["db"].Port != 5432 {
		t.Fatalf("db service = %+v", byName["db"])
	}
	// The compose db service is also the strongest database signal.
	if res.SuggestedDatabase != "postgres" {
		t.Fatalf("SuggestedDatabase = %q, want postgres", res.SuggestedDatabase)
	}
}

func TestComposePreferredOverRootWhenNested(t *testing.T) {
	res := FromTree(tree(map[string]string{
		"deploy/compose.yaml": "services:\n  app:\n    build: .\n",
	}))
	if res.ComposePreview == nil || res.ComposePreview.Path != "deploy/compose.yaml" {
		t.Fatalf("ComposePreview = %+v", res.ComposePreview)
	}
}

func TestDetectDatabaseEnvConnectionString(t *testing.T) {
	res := FromTree(tree(map[string]string{
		".env": "DATABASE_URL=postgres://user:pass@host:5432/db\n",
	}))
	if res.SuggestedDatabase != "postgres" {
		t.Fatalf("SuggestedDatabase = %q, want postgres", res.SuggestedDatabase)
	}
	if res.DatabaseReason == "" {
		t.Fatal("expected a non-empty reason")
	}
}

func TestDetectDatabaseDynamoDBFromComposeImage(t *testing.T) {
	res := FromTree(tree(map[string]string{
		"compose.yaml": "services:\n  db:\n    image: amazon/dynamodb-local\n",
	}))
	if res.SuggestedDatabase != "dynamodb" {
		t.Fatalf("SuggestedDatabase = %q, want dynamodb", res.SuggestedDatabase)
	}
}

func TestDetectDatabasePrismaProviderIgnoresGenerator(t *testing.T) {
	res := FromTree(tree(map[string]string{
		"schema.prisma": "generator client {\n  provider = \"prisma-client-js\"\n}\ndatasource db {\n  provider = \"postgresql\"\n  url = env(\"DATABASE_URL\")\n}\n",
	}))
	if res.SuggestedDatabase != "postgres" {
		t.Fatalf("SuggestedDatabase = %q, want postgres", res.SuggestedDatabase)
	}
}

func TestDetectDatabaseWeakSignalFromManifestOnly(t *testing.T) {
	res := FromTree(tree(map[string]string{
		"package.json": `{"dependencies": {"pg": "^8.0.0"}}`,
	}))
	if res.SuggestedDatabase != "postgres" {
		t.Fatalf("SuggestedDatabase = %q, want postgres", res.SuggestedDatabase)
	}
}

func TestDetectDatabaseStrongSignalBeatsWeak(t *testing.T) {
	res := FromTree(tree(map[string]string{
		"package.json": `{"dependencies": {"pg": "^8.0.0"}}`,
		".env":         "DATABASE_URL=mysql://user:pass@host:3306/db\n",
	}))
	if res.SuggestedDatabase != "postgres" {
		t.Fatalf("SuggestedDatabase = %q, want postgres", res.SuggestedDatabase)
	}
	if res.DatabaseReason == "" || res.DatabaseReason[:6] != "mysql " {
		t.Fatalf("DatabaseReason = %q, want the env connection string to win", res.DatabaseReason)
	}
}

func TestDetectDatabaseNoSignal(t *testing.T) {
	res := FromTree(tree(map[string]string{"Dockerfile": "FROM node:20\n"}))
	if res.SuggestedDatabase != "" || res.DatabaseReason != "" {
		t.Fatalf("unexpected database guess: %q / %q", res.SuggestedDatabase, res.DatabaseReason)
	}
}
