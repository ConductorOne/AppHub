// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// dynamoAPI is the slice of the DynamoDB API this package actually calls.
//
// It is unexported on purpose, and that is the load-bearing half of the fence.
// An exported interface over DynamoDB would be a DynamoDB abstraction with a
// different name: callers outside store could accept one, and the SDK types in
// its signatures would be back in business logic. Unexported means the only
// implementations are the real client and this package's own test double.
//
// The source system had no seam here at all -- repositories held a
// *dynamodb.Client directly (internal/database/client.go:16-19), so nothing in
// 23,490 lines of persistence code could be tested without a live table.
type dynamoAPI interface {
	PutItem(context.Context, *dynamodb.PutItemInput, ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	GetItem(context.Context, *dynamodb.GetItemInput, ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	DeleteItem(context.Context, *dynamodb.DeleteItemInput, ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)
	UpdateItem(context.Context, *dynamodb.UpdateItemInput, ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
	TransactWriteItems(context.Context, *dynamodb.TransactWriteItemsInput, ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error)
	Query(context.Context, *dynamodb.QueryInput, ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error)
	Scan(context.Context, *dynamodb.ScanInput, ...func(*dynamodb.Options)) (*dynamodb.ScanOutput, error)
}

// Single-table layout. Every record type this package stores shares one table
// and is distinguished by a PK prefix and the Type attribute, which is the
// design the source system used and the reason a Scan needs a Type filter at
// all.
const (
	// indexGSI1 is the one global secondary index the layout defines.
	indexGSI1 = "GSI1"

	// attrPK and attrSK name the table's key attributes.
	attrPK = "PK"
	attrSK = "SK"

	// skMetadata is the sort key for an entity's own attributes, as opposed to a
	// child item beneath the same partition (internal/database/models.go:26).
	skMetadata = "METADATA"
)

// Config is what an adopter must supply to reach a table.
//
// Region and TableName are required and have no defaults. AuditTableName is
// optional for isolated legacy store callers, but the apphub composition root
// always supplies a distinct audit table and checks its readiness. A default
// state table name here could silently read and write another deployment's data.
type Config struct {
	// Region is the AWS region holding the table.
	Region string

	// TableName is the DynamoDB table. Required, no default.
	TableName string

	// AuditTableName is a separate table for append-only audit events.
	AuditTableName string

	// Endpoint overrides the service endpoint. Empty means the real AWS
	// endpoint for Region.
	//
	// This exists for an adopter pointing at their own DynamoDB-compatible
	// endpoint. It deliberately does not carry credentials: the source's
	// equivalent constructor hard-coded a static access key pair for local use
	// (internal/database/client.go:36-43), and a credential literal in a public
	// repository is a credential literal regardless of what it unlocks. The
	// ambient AWS credential chain is used either way.
	Endpoint string
}

func (c Config) validate() error {
	if c.Region == "" {
		return errors.New("store: Region is required")
	}
	if c.TableName == "" {
		return errors.New("store: TableName is required")
	}
	if c.AuditTableName != "" && c.AuditTableName == c.TableName {
		return errors.New("store: AuditTableName must differ from TableName")
	}
	return nil
}

// Client is a handle on the table. It is the only type in AppHub that holds a
// DynamoDB client, and it does not hand it out.
//
// The source exposed its raw client through a DynamoDB() accessor
// (internal/database/client.go:71-73). That accessor is deliberately not ported:
// one caller reaching through it puts SDK types back into business logic and the
// fence stops meaning anything.
type Client struct {
	api            dynamoAPI
	tableName      string
	auditTableName string
}

// New builds a Client from the ambient AWS configuration.
func New(ctx context.Context, cfg Config) (*Client, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.Region))
	if err != nil {
		return nil, fmt.Errorf("store: load AWS config: %w", err)
	}

	var opts []func(*dynamodb.Options)
	if cfg.Endpoint != "" {
		opts = append(opts, func(o *dynamodb.Options) { o.BaseEndpoint = aws.String(cfg.Endpoint) })
	}

	return &Client{
		api:            dynamodb.NewFromConfig(awsCfg, opts...),
		tableName:      cfg.TableName,
		auditTableName: cfg.AuditTableName,
	}, nil
}

// TableName reports the table this Client targets. It is a string for logs and
// diagnostics, not a handle on anything.
func (c *Client) TableName() string { return c.tableName }

// conditionFailed reports whether err is DynamoDB refusing a write because its
// ConditionExpression did not hold.
//
// Every optimistic-concurrency and existence guarantee in this package is a
// conditional write, so this predicate is what turns a transport error into one
// of lifecycle's sentinels. errors.As rather than a string match: the SDK models
// this as a typed error and matching on message text would break on a wording
// change nobody would think to check.
func conditionFailed(err error) bool {
	var cfe *types.ConditionalCheckFailedException
	return errors.As(err, &cfe)
}
