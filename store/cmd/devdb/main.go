// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Command devdb manages the local DynamoDB state and audit tables used by AppHub development.
//
// It lives below store/ because it necessarily knows DynamoDB's table schema
// and API. The public packages remain fenced from those details.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/credentials/lifecycle"
	"github.com/conductorone/apphub/store"
)

const (
	defaultEndpoint = "http://127.0.0.1:18000"
	defaultRegion   = "us-east-1"
	defaultTable    = "apphub-local"
	readyTimeout    = 30 * time.Second
)

type databaseConfig struct {
	endpoint string
	region   string
	table    string
}

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return usage()
	}

	switch args[0] {
	case "env":
		return writeEnvironment(args[1:])
	case "init", "reset", "seed", "scan", "tables":
		cfg, err := parseDatabaseConfig(args[1:])
		if err != nil {
			return err
		}
		client, err := newClient(ctx, cfg)
		if err != nil {
			return err
		}
		switch args[0] {
		case "init":
			if err := ensureTable(ctx, client, cfg.table); err != nil {
				return err
			}
			if err := ensureAuditTable(ctx, client, cfg.table+"-audit"); err != nil {
				return err
			}
			_, err := fmt.Fprintf(out, "local DynamoDB tables %q and %q are active\n", cfg.table, cfg.table+"-audit")
			return err
		case "reset":
			if err := resetTable(ctx, client, cfg.table); err != nil {
				return err
			}
			if err := resetAuditTable(ctx, client, cfg.table+"-audit"); err != nil {
				return err
			}
			_, err := fmt.Fprintf(out, "local DynamoDB tables %q and %q were reset\n", cfg.table, cfg.table+"-audit")
			return err
		case "seed":
			return seed(ctx, cfg, out)
		case "scan":
			return scan(ctx, client, cfg.table, out)
		case "tables":
			return listTables(ctx, client, out)
		}
	}
	return usage()
}

func usage() error {
	return errors.New("usage: devdb <env|init|reset|seed|scan|tables> [flags]")
}

func parseDatabaseConfig(args []string) (databaseConfig, error) {
	flags := flag.NewFlagSet("devdb", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	cfg := databaseConfig{}
	flags.StringVar(&cfg.endpoint, "endpoint", defaultEndpoint, "DynamoDB endpoint")
	flags.StringVar(&cfg.region, "region", defaultRegion, "AWS region")
	flags.StringVar(&cfg.table, "table", defaultTable, "DynamoDB table name")
	if err := flags.Parse(args); err != nil {
		return databaseConfig{}, err
	}
	if flags.NArg() != 0 {
		return databaseConfig{}, fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	if strings.TrimSpace(cfg.endpoint) == "" || strings.TrimSpace(cfg.region) == "" || strings.TrimSpace(cfg.table) == "" {
		return databaseConfig{}, errors.New("endpoint, region, and table are required")
	}
	return cfg, nil
}

func writeEnvironment(args []string) error {
	flags := flag.NewFlagSet("devdb env", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := ".env.local"
	endpoint := defaultEndpoint
	flags.StringVar(&path, "file", path, "local environment file")
	flags.StringVar(&endpoint, "endpoint", endpoint, "DynamoDB endpoint written as AWS_ENDPOINT_URL")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || strings.TrimSpace(path) == "" || strings.TrimSpace(endpoint) == "" {
		return errors.New("env requires only a non-empty -file and -endpoint")
	}
	if environmentFileUsable(path) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create environment directory: %w", err)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("replace local environment file: %w", err)
	}

	accessKey, err := randomValue()
	if err != nil {
		return fmt.Errorf("generate local access key: %w", err)
	}
	secretKey, err := randomValue()
	if err != nil {
		return fmt.Errorf("generate local secret key: %w", err)
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create local environment file: %w", err)
	}
	_, writeErr := fmt.Fprintf(file, "AWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\nAWS_EC2_METADATA_DISABLED=true\nAWS_ENDPOINT_URL=%s\nAWS_SESSION_TOKEN=\nAWS_SECURITY_TOKEN=\n", accessKey, secretKey, endpoint)
	closeErr := file.Close()
	if writeErr != nil {
		return fmt.Errorf("write local environment file: %w", writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close local environment file: %w", closeErr)
	}
	return nil
}

// DynamoDB Local 2.0+ rejects an access key that is not letters and digits
// only. Base64 therefore cannot be used: "-" and "_" produce
// UnrecognizedClientException. The values are still random; they are just
// drawn from the alphabet DynamoDB Local will accept.
const localCredentialAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

func randomValue() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	out := make([]byte, len(value))
	for i, b := range value {
		out[i] = localCredentialAlphabet[int(b)%len(localCredentialAlphabet)]
	}
	return string(out), nil
}

func environmentFileUsable(path string) bool {
	// #nosec G304 -- path is the local development credential file selected by this CLI.
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || key != "AWS_ACCESS_KEY_ID" {
			continue
		}
		if value == "" {
			return false
		}
		for _, r := range value {
			if (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
				return false
			}
		}
		return true
	}
	return false
}

func newClient(ctx context.Context, cfg databaseConfig) (*dynamodb.Client, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.region))
	if err != nil {
		return nil, fmt.Errorf("load AWS configuration: %w", err)
	}
	return dynamodb.NewFromConfig(awsCfg, func(options *dynamodb.Options) {
		options.BaseEndpoint = aws.String(cfg.endpoint)
	}), nil
}

func ensureTable(ctx context.Context, client *dynamodb.Client, table string) error {
	ctx, cancel := context.WithTimeout(ctx, readyTimeout)
	defer cancel()
	if err := waitForServer(ctx, client); err != nil {
		return err
	}

	_, err := client.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(table)})
	if err == nil {
		if err := waitForActive(ctx, client, table); err != nil {
			return err
		}
		return ensureControlPlaneSchema(ctx, client, table)
	}
	var missing *types.ResourceNotFoundException
	if !errors.As(err, &missing) {
		return fmt.Errorf("describe table %q: %w", table, err)
	}

	_, err = client.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName:   aws.String(table),
		BillingMode: types.BillingModePayPerRequest,
		AttributeDefinitions: []types.AttributeDefinition{
			{AttributeName: aws.String("PK"), AttributeType: types.ScalarAttributeTypeS},
			{AttributeName: aws.String("SK"), AttributeType: types.ScalarAttributeTypeS},
			{AttributeName: aws.String("GSI1PK"), AttributeType: types.ScalarAttributeTypeS},
			{AttributeName: aws.String("GSI1SK"), AttributeType: types.ScalarAttributeTypeS},
		},
		KeySchema: []types.KeySchemaElement{
			{AttributeName: aws.String("PK"), KeyType: types.KeyTypeHash},
			{AttributeName: aws.String("SK"), KeyType: types.KeyTypeRange},
		},
		GlobalSecondaryIndexes: []types.GlobalSecondaryIndex{{
			IndexName:  aws.String("GSI1"),
			KeySchema:  controlPlaneIndexKeys(),
			Projection: &types.Projection{ProjectionType: types.ProjectionTypeAll},
		}},
	})
	if err != nil {
		var exists *types.ResourceInUseException
		if !errors.As(err, &exists) {
			return fmt.Errorf("create table %q: %w", table, err)
		}
	}
	if err := waitForActive(ctx, client, table); err != nil {
		return err
	}
	return ensureControlPlaneSchema(ctx, client, table)
}

// Audit events have their own chronological table: PK="AUDIT", SK=UTC
// timestamp followed by a unique ID. expiresAt is a Unix-seconds TTL set by
// the writer 400 days after occurrence; DynamoDB removes expired items
// asynchronously.
func ensureAuditTable(ctx context.Context, client *dynamodb.Client, table string) error {
	ctx, cancel := context.WithTimeout(ctx, readyTimeout)
	defer cancel()
	if err := waitForServer(ctx, client); err != nil {
		return err
	}
	_, err := client.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(table)})
	if err != nil {
		var missing *types.ResourceNotFoundException
		if !errors.As(err, &missing) {
			return fmt.Errorf("describe audit table %q: %w", table, err)
		}
		_, err = client.CreateTable(ctx, &dynamodb.CreateTableInput{
			TableName:   aws.String(table),
			BillingMode: types.BillingModePayPerRequest,
			AttributeDefinitions: []types.AttributeDefinition{
				{AttributeName: aws.String("PK"), AttributeType: types.ScalarAttributeTypeS},
				{AttributeName: aws.String("SK"), AttributeType: types.ScalarAttributeTypeS},
			},
			KeySchema: []types.KeySchemaElement{
				{AttributeName: aws.String("PK"), KeyType: types.KeyTypeHash},
				{AttributeName: aws.String("SK"), KeyType: types.KeyTypeRange},
			},
		})
		if err != nil {
			var exists *types.ResourceInUseException
			if !errors.As(err, &exists) {
				return fmt.Errorf("create audit table %q: %w", table, err)
			}
		}
	}
	if err := waitForActive(ctx, client, table); err != nil {
		return err
	}
	description, err := client.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(table)})
	if err != nil {
		return fmt.Errorf("describe audit table schema: %w", err)
	}
	if description.Table == nil || len(description.Table.KeySchema) != 2 ||
		len(description.Table.GlobalSecondaryIndexes) != 0 || len(description.Table.LocalSecondaryIndexes) != 0 {
		return errors.New("audit table has an incompatible key or index schema")
	}
	keys := 0
	for _, key := range description.Table.KeySchema {
		if (aws.ToString(key.AttributeName) == "PK" && key.KeyType == types.KeyTypeHash) ||
			(aws.ToString(key.AttributeName) == "SK" && key.KeyType == types.KeyTypeRange) {
			keys++
		}
	}
	if keys != 2 {
		return errors.New("audit table has incompatible keys")
	}
	attributes := 0
	for _, attribute := range description.Table.AttributeDefinitions {
		if (aws.ToString(attribute.AttributeName) == "PK" || aws.ToString(attribute.AttributeName) == "SK") &&
			attribute.AttributeType == types.ScalarAttributeTypeS {
			attributes++
		}
	}
	if attributes != 2 {
		return errors.New("audit table keys must be strings")
	}
	ttlOutput, err := client.DescribeTimeToLive(ctx, &dynamodb.DescribeTimeToLiveInput{TableName: aws.String(table)})
	if err != nil {
		return fmt.Errorf("describe audit TTL: %w", err)
	}
	if ttlOutput.TimeToLiveDescription != nil {
		ttl := ttlOutput.TimeToLiveDescription
		if ttl.TimeToLiveStatus == types.TimeToLiveStatusEnabled || ttl.TimeToLiveStatus == types.TimeToLiveStatusEnabling {
			if aws.ToString(ttl.AttributeName) != "expiresAt" {
				return errors.New("audit table has an incompatible TTL attribute")
			}
			return nil
		}
		if ttl.TimeToLiveStatus == types.TimeToLiveStatusDisabling {
			return errors.New("audit table TTL is being disabled; retry initialization after it settles")
		}
	}
	_, err = client.UpdateTimeToLive(ctx, &dynamodb.UpdateTimeToLiveInput{
		TableName: aws.String(table),
		TimeToLiveSpecification: &types.TimeToLiveSpecification{
			AttributeName: aws.String("expiresAt"),
			Enabled:       aws.Bool(true),
		},
	})
	if err != nil {
		return fmt.Errorf("enable audit TTL: %w", err)
	}
	return nil
}

func controlPlaneIndexKeys() []types.KeySchemaElement {
	return []types.KeySchemaElement{
		{AttributeName: aws.String("GSI1PK"), KeyType: types.KeyTypeHash},
		{AttributeName: aws.String("GSI1SK"), KeyType: types.KeyTypeRange},
	}
}

// Initialization upgrades an existing local table in place; it never resets
// developer records merely because a newly used index has not been provisioned.
func ensureControlPlaneSchema(ctx context.Context, client *dynamodb.Client, table string) error {
	for {
		out, err := client.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(table)})
		if err != nil {
			return fmt.Errorf("describe table schema: %w", err)
		}
		if out.Table == nil {
			return errors.New("table schema is missing")
		}
		var index *types.GlobalSecondaryIndexDescription
		for i := range out.Table.GlobalSecondaryIndexes {
			if aws.ToString(out.Table.GlobalSecondaryIndexes[i].IndexName) == "GSI1" {
				index = &out.Table.GlobalSecondaryIndexes[i]
				break
			}
		}
		if index == nil {
			_, err = client.UpdateTable(ctx, &dynamodb.UpdateTableInput{
				TableName: aws.String(table),
				AttributeDefinitions: []types.AttributeDefinition{
					{AttributeName: aws.String("GSI1PK"), AttributeType: types.ScalarAttributeTypeS},
					{AttributeName: aws.String("GSI1SK"), AttributeType: types.ScalarAttributeTypeS},
				},
				GlobalSecondaryIndexUpdates: []types.GlobalSecondaryIndexUpdate{{Create: &types.CreateGlobalSecondaryIndexAction{
					IndexName: aws.String("GSI1"), KeySchema: controlPlaneIndexKeys(),
					Projection: &types.Projection{ProjectionType: types.ProjectionTypeAll},
				}}},
			})
			if err != nil {
				var concurrent *types.ResourceInUseException
				if !errors.As(err, &concurrent) {
					return fmt.Errorf("add GSI1: %w", err)
				}
			}
		} else {
			if err := validateControlPlaneIndex(*index); err != nil {
				return err
			}
			if index.IndexStatus == types.IndexStatusActive && !aws.ToBool(index.Backfilling) {
				break
			}
		}
		if err := wait(ctx); err != nil {
			return fmt.Errorf("wait for GSI1: %w", err)
		}
	}
	out, err := client.DescribeTimeToLive(ctx, &dynamodb.DescribeTimeToLiveInput{TableName: aws.String(table)})
	if err != nil {
		return fmt.Errorf("describe cleanup TTL: %w", err)
	}
	if out.TimeToLiveDescription != nil {
		ttl := out.TimeToLiveDescription
		if ttl.TimeToLiveStatus == types.TimeToLiveStatusEnabled || ttl.TimeToLiveStatus == types.TimeToLiveStatusEnabling {
			if aws.ToString(ttl.AttributeName) != "TTL" {
				return errors.New("table has an incompatible TTL attribute")
			}
			return nil
		}
		if ttl.TimeToLiveStatus == types.TimeToLiveStatusDisabling {
			return errors.New("table TTL is being disabled; retry initialization after it settles")
		}
	}
	_, err = client.UpdateTimeToLive(ctx, &dynamodb.UpdateTimeToLiveInput{TableName: aws.String(table), TimeToLiveSpecification: &types.TimeToLiveSpecification{AttributeName: aws.String("TTL"), Enabled: aws.Bool(true)}})
	if err != nil {
		return fmt.Errorf("enable cleanup TTL: %w", err)
	}
	return nil
}

func validateControlPlaneIndex(index types.GlobalSecondaryIndexDescription) error {
	if index.Projection == nil || index.Projection.ProjectionType != types.ProjectionTypeAll || len(index.KeySchema) != 2 {
		return errors.New("GSI1 has an incompatible schema")
	}
	found := 0
	for _, key := range index.KeySchema {
		if (key.KeyType == types.KeyTypeHash && aws.ToString(key.AttributeName) == "GSI1PK") || (key.KeyType == types.KeyTypeRange && aws.ToString(key.AttributeName) == "GSI1SK") {
			found++
		}
	}
	if found != 2 {
		return errors.New("GSI1 has incompatible keys")
	}
	return nil
}

func resetTable(ctx context.Context, client *dynamodb.Client, table string) error {
	return resetNamedTable(ctx, client, table, ensureTable)
}

func resetAuditTable(ctx context.Context, client *dynamodb.Client, table string) error {
	return resetNamedTable(ctx, client, table, ensureAuditTable)
}

func resetNamedTable(ctx context.Context, client *dynamodb.Client, table string, ensure func(context.Context, *dynamodb.Client, string) error) error {
	ctx, cancel := context.WithTimeout(ctx, readyTimeout)
	defer cancel()
	if err := waitForServer(ctx, client); err != nil {
		return err
	}
	_, err := client.DeleteTable(ctx, &dynamodb.DeleteTableInput{TableName: aws.String(table)})
	if err != nil {
		var missing *types.ResourceNotFoundException
		if !errors.As(err, &missing) {
			return fmt.Errorf("delete table %q: %w", table, err)
		}
	} else if err := waitForMissing(ctx, client, table); err != nil {
		return err
	}
	return ensure(ctx, client, table)
}

func waitForServer(ctx context.Context, client *dynamodb.Client) error {
	var last error
	for {
		_, err := client.ListTables(ctx, &dynamodb.ListTablesInput{Limit: aws.Int32(1)})
		if err == nil {
			return nil
		}
		last = err
		if err := wait(ctx); err != nil {
			if last != nil {
				return fmt.Errorf("wait for DynamoDB Local: %w (last error: %w)", err, last)
			}
			return fmt.Errorf("wait for DynamoDB Local: %w", err)
		}
	}
}

func waitForActive(ctx context.Context, client *dynamodb.Client, table string) error {
	for {
		output, err := client.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(table)})
		if err == nil && output.Table != nil && output.Table.TableStatus == types.TableStatusActive {
			return nil
		}
		if err != nil {
			var missing *types.ResourceNotFoundException
			if !errors.As(err, &missing) {
				return fmt.Errorf("wait for table %q: %w", table, err)
			}
		}
		if err := wait(ctx); err != nil {
			return fmt.Errorf("wait for table %q to become active: %w", table, err)
		}
	}
}

func waitForMissing(ctx context.Context, client *dynamodb.Client, table string) error {
	for {
		_, err := client.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(table)})
		var missing *types.ResourceNotFoundException
		if errors.As(err, &missing) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("wait for table %q deletion: %w", table, err)
		}
		if err := wait(ctx); err != nil {
			return fmt.Errorf("wait for table %q deletion: %w", table, err)
		}
	}
}

func wait(ctx context.Context) error {
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func seed(ctx context.Context, cfg databaseConfig, out io.Writer) error {
	client, err := store.New(ctx, store.Config{Region: cfg.region, TableName: cfg.table, Endpoint: cfg.endpoint})
	if err != nil {
		return err
	}
	records, err := store.NewCredentialRecords(client, lifecycle.NewAnnotationRegistry())
	if err != nil {
		return err
	}

	inserted := 0
	for _, record := range sampleRecords(time.Now().UTC()) {
		if err := records.Create(ctx, record); err != nil {
			if errors.Is(err, lifecycle.ErrAlreadyExists) {
				continue
			}
			return fmt.Errorf("seed record %q: %w", record.ID, err)
		}
		inserted++
	}
	_, err = fmt.Fprintf(out, "seeded %d local lifecycle record(s)\n", inserted)
	return err
}

func sampleRecords(now time.Time) []*lifecycle.Record {
	revokedAt := now.Add(-time.Hour)
	return []*lifecycle.Record{
		{
			ID:                  "dev-active",
			ProviderID:          "dev",
			Type:                credentials.CredentialTypeDynamic,
			Name:                "local-active-credential",
			PlatformKeyID:       "local-active",
			IdempotencyKey:      "dev-active",
			Requester:           lifecycle.Requester{ID: "dev-user", Type: "user", Email: "developer@example.invalid"},
			Status:              lifecycle.StatusActive,
			GrantedScope:        []string{"read:widgets"},
			RequestedScope:      []string{"read:widgets", "write:widgets"},
			ApplicationID:       "dev-app",
			ExpiresAt:           now.Add(24 * time.Hour),
			ExpiryAuthoritative: true,
			CreatedAt:           now.Add(-15 * time.Minute),
			LastRefreshedAt:     now.Add(-5 * time.Minute),
		},
		{
			ID:             "dev-pending",
			ProviderID:     "dev",
			Type:           credentials.CredentialTypeDynamic,
			Name:           "local-pending-credential",
			PlatformKeyID:  "local-pending",
			IdempotencyKey: "dev-pending",
			Requester:      lifecycle.Requester{ID: "dev-user", Type: "user", Email: "developer@example.invalid"},
			Status:         lifecycle.StatusPending,
			RequestedScope: []string{"read:widgets"},
			ApplicationID:  "dev-app",
			ExpiresAt:      now.Add(time.Hour),
			CreatedAt:      now.Add(-2 * time.Minute),
		},
		{
			ID:                  "dev-revoked",
			ProviderID:          "dev",
			Type:                credentials.CredentialTypeStatic,
			Name:                "local-revoked-credential",
			PlatformKeyID:       "local-revoked",
			IdempotencyKey:      "dev-revoked",
			Requester:           lifecycle.Requester{ID: "dev-user", Type: "user", Email: "developer@example.invalid"},
			Status:              lifecycle.StatusRevoked,
			RevokeOutcome:       lifecycle.RevokeOutcomeUpstream,
			RequestedScope:      []string{"admin:widgets"},
			ApplicationID:       "dev-app",
			ExpiresAt:           now.Add(-time.Hour),
			ExpiryAuthoritative: true,
			CreatedAt:           now.Add(-48 * time.Hour),
			UpdatedAt:           revokedAt,
			RevokedAt:           &revokedAt,
		},
	}
}

func scan(ctx context.Context, client *dynamodb.Client, table string, out io.Writer) error {
	var items []map[string]any
	var startKey map[string]types.AttributeValue
	for {
		page, err := client.Scan(ctx, &dynamodb.ScanInput{TableName: aws.String(table), ExclusiveStartKey: startKey})
		if err != nil {
			return fmt.Errorf("scan table %q: %w", table, err)
		}
		for _, item := range page.Items {
			decoded := make(map[string]any, len(item))
			for key, value := range item {
				decoded[key] = decode(value)
			}
			items = append(items, decoded)
		}
		if len(page.LastEvaluatedKey) == 0 {
			break
		}
		startKey = page.LastEvaluatedKey
	}
	return json.NewEncoder(out).Encode(items)
}

func listTables(ctx context.Context, client *dynamodb.Client, out io.Writer) error {
	var names []string
	var start string
	for {
		page, err := client.ListTables(ctx, &dynamodb.ListTablesInput{ExclusiveStartTableName: aws.String(start)})
		if err != nil {
			return fmt.Errorf("list tables: %w", err)
		}
		names = append(names, page.TableNames...)
		if page.LastEvaluatedTableName == nil {
			break
		}
		start = *page.LastEvaluatedTableName
	}
	return json.NewEncoder(out).Encode(names)
}

func decode(value types.AttributeValue) any {
	switch value := value.(type) {
	case *types.AttributeValueMemberB:
		return base64.StdEncoding.EncodeToString(value.Value)
	case *types.AttributeValueMemberBOOL:
		return value.Value
	case *types.AttributeValueMemberBS:
		out := make([]string, len(value.Value))
		for i := range value.Value {
			out[i] = base64.StdEncoding.EncodeToString(value.Value[i])
		}
		return out
	case *types.AttributeValueMemberL:
		out := make([]any, len(value.Value))
		for i := range value.Value {
			out[i] = decode(value.Value[i])
		}
		return out
	case *types.AttributeValueMemberM:
		out := make(map[string]any, len(value.Value))
		for key, nested := range value.Value {
			out[key] = decode(nested)
		}
		return out
	case *types.AttributeValueMemberN:
		return value.Value
	case *types.AttributeValueMemberNS:
		return value.Value
	case *types.AttributeValueMemberNULL:
		return nil
	case *types.AttributeValueMemberS:
		return value.Value
	case *types.AttributeValueMemberSS:
		return value.Value
	default:
		return fmt.Sprintf("unsupported DynamoDB attribute %T", value)
	}
}
