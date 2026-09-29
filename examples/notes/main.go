// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Command notes is a reference application for AppHub: a per-user notes service
// that stores its data in the DynamoDB table AppHub provisions for it.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// listenAddr must match the port in the AppHub spec and the Dockerfile's EXPOSE.
const listenAddr = ":8080"

// settings is everything the process reads from its environment.
type settings struct {
	// table is TABLE_NAME, which AppHub sets when the app has a key-value table.
	table string
	// localEndpoint is LOCAL_DYNAMO_ENDPOINT, a DynamoDB Local URL for
	// development. Never set on AppHub.
	localEndpoint string
	// devEmail is DEV_USER_EMAIL, the identity to assume when no sign-in
	// header arrives. Honoured only with localEndpoint, so a stray value in a
	// deployed app cannot sign anyone in.
	devEmail string
}

func loadSettings() (settings, error) {
	s := settings{
		table:         os.Getenv("TABLE_NAME"),
		localEndpoint: os.Getenv("LOCAL_DYNAMO_ENDPOINT"),
		devEmail:      os.Getenv("DEV_USER_EMAIL"),
	}
	if s.table == "" {
		return settings{}, errors.New("TABLE_NAME is not set: attach a key-value database to this " +
			"application in AppHub, or set TABLE_NAME for local development")
	}
	if s.devEmail != "" && s.localEndpoint == "" {
		return settings{}, errors.New("DEV_USER_EMAIL is set without LOCAL_DYNAMO_ENDPOINT; " +
			"it is for local development only")
	}
	return s, nil
}

// dynamoClient uses the default AWS credential chain, which on AppHub resolves
// to the task role that has access to the table. Locally it points at DynamoDB
// Local, which accepts any credentials.
func dynamoClient(ctx context.Context, s settings) (*dynamodb.Client, error) {
	var opts []func(*config.LoadOptions) error
	if s.localEndpoint != "" {
		opts = append(opts,
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("local", "local", "")),
			config.WithRegion("us-east-1"),
		)
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("loading AWS configuration: %w", err)
	}
	return dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
		if s.localEndpoint != "" {
			o.BaseEndpoint = aws.String(s.localEndpoint)
		}
	}), nil
}

// ensureLocalTable creates the table in DynamoDB Local with the key schema
// AppHub gives a key-value table. On AppHub the table already exists and the
// app has no permission to create one.
func ensureLocalTable(ctx context.Context, client *dynamodb.Client, table string) error {
	_, err := client.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName:   aws.String(table),
		BillingMode: types.BillingModePayPerRequest,
		KeySchema: []types.KeySchemaElement{
			{AttributeName: aws.String(attrPK), KeyType: types.KeyTypeHash},
			{AttributeName: aws.String(attrSK), KeyType: types.KeyTypeRange},
		},
		AttributeDefinitions: []types.AttributeDefinition{
			{AttributeName: aws.String(attrPK), AttributeType: types.ScalarAttributeTypeS},
			{AttributeName: aws.String(attrSK), AttributeType: types.ScalarAttributeTypeS},
		},
	})
	var exists *types.ResourceInUseException
	if err != nil && !errors.As(err, &exists) {
		return fmt.Errorf("creating local table %s: %w", table, err)
	}
	return nil
}

func run(ctx context.Context, log *slog.Logger) error {
	s, err := loadSettings()
	if err != nil {
		return err
	}
	client, err := dynamoClient(ctx, s)
	if err != nil {
		return err
	}
	if s.localEndpoint != "" {
		if err := ensureLocalTable(ctx, client, s.table); err != nil {
			return err
		}
	}
	app := &App{store: NewDynamoStore(client, s.table), devEmail: s.devEmail, log: log}
	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           app.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("listening", "addr", listenAddr, "table", s.table)

	select {
	case err := <-errc:
		return fmt.Errorf("serving on %s: %w", listenAddr, err)
	case <-ctx.Done():
	}
	// ECS sends SIGTERM and waits 30 seconds before killing the task.
	shutdown, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	log.Info("shutting down")
	return srv.Shutdown(shutdown)
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	if err := run(ctx, log); err != nil {
		log.Error("notes stopped", "error", err)
		os.Exit(1)
	}
}
