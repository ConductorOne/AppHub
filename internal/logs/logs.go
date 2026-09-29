// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package logs is the narrow, read-only CloudWatch Logs surface the
// authenticated API process ("serve") holds directly -- unlike every other
// AWS capability in this repository, which lives only in the isolated
// worker.
//
// # Why this is the one exception
//
// [Reader] only ever reads: FilterLogEvents against an operator-named log
// group. Nothing here can write, delete, or configure infrastructure, and
// nothing here can name a log group serve was not explicitly told to read
// (see below). An admin viewing platform logs is expected to feel
// immediate, and the durable worker-dispatch pattern this repository uses
// for everything else that needs real AWS credentials (a deploy, or
// repository detection -- internal/worker.Detector) is built for operations
// that take seconds to minutes and tolerate a poll; a log tail is not one of
// those. The operator scopes serve's own IAM identity to exactly
// logs:FilterLogEvents on the configured log groups and nothing else; this
// package does not choose or enforce that policy, it only uses whatever
// credentials the process's ambient chain provides -- the same
// config.LoadDefaultConfig chain compute/aws uses, an IAM role on the
// running task in production.
//
// # What is named, and by whom
//
// Every log group this package can read is named by an operator in
// [github.com/conductorone/apphub/internal/serverconfig.ObservabilityConfig],
// never inferred or composed from an application or resource name. That
// mirrors the rest of this repository: no identifier here is compiled in,
// and a caller supplies the exact log group name, not a name this package
// would derive.
package logs

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
)

// Bounds on one Filter call. maxWindow exists so an open-ended admin request
// cannot turn into an unbounded scan of a log group's entire retention
// period; the others mirror CloudWatch's own request limits.
const (
	defaultLimit     int32 = 200
	maxLimit         int32 = 10000
	maxFilterPattern       = 2048
	maxNextToken           = 8192
	maxWindow              = 7 * 24 * time.Hour
)

// Errors are deliberately generic: this package never returns AWS's own
// error text to a caller, the same rule [github.com/conductorone/apphub/internal/githubapp]
// follows for the same reason -- a transport failure's diagnostic text is not
// something this process should echo back to an HTTP response.
var (
	ErrConfiguration = errors.New("logs: invalid configuration")
	ErrUnavailable   = errors.New("logs: CloudWatch Logs unavailable")
	ErrInvalidQuery  = errors.New("logs: invalid query")
)

// Event is one CloudWatch log event.
type Event struct {
	Timestamp     time.Time `json:"timestamp"`
	Message       string    `json:"message"`
	LogStreamName string    `json:"logStreamName"`
}

// Query bounds one FilterLogEvents call.
type Query struct {
	// Start and End bound the query window; both are required and Start must
	// be strictly before End.
	Start, End time.Time
	// FilterPattern is CloudWatch's own filter-pattern syntax, passed through
	// unmodified. Empty matches every event in the window.
	FilterPattern string
	// NextToken continues a prior Result.
	NextToken string
	// Limit bounds how many events one call returns. Zero means defaultLimit.
	Limit int32
}

// Result is one page of matching events.
type Result struct {
	Events []Event `json:"events"`
	// NextToken is set when more events may exist past this page.
	NextToken string `json:"nextToken,omitempty"`
}

// API is the CloudWatch Logs operation [Reader] calls. A narrow interface
// over the generated client -- satisfied by *cloudwatchlogs.Client -- so
// this package's own validation and translation logic can be tested against
// the SDK's own error shapes without a live AWS account.
type API interface {
	FilterLogEvents(ctx context.Context, in *cloudwatchlogs.FilterLogEventsInput, opts ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.FilterLogEventsOutput, error)
}

// Reader answers a bounded FilterLogEvents query against one named log group.
//
// It holds no state naming which groups are permitted to be read -- that
// allowlist lives in the caller (internal/controlplane.Service), which is
// what keeps this package a pure translation layer, the same split
// compute/aws/ssmclient.go documents for its own SSM translation layer.
type Reader struct{ api API }

// NewReader loads AWS configuration from the process's ambient credential
// chain for the given region and constructs a Reader. It performs no network
// I/O of its own; the SDK resolves credentials lazily on first call.
func NewReader(ctx context.Context, region string) (*Reader, error) {
	if region == "" {
		return nil, fmt.Errorf("%w: region is required", ErrConfiguration)
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("%w: AWS configuration could not be loaded", ErrConfiguration)
	}
	return &Reader{api: cloudwatchlogs.NewFromConfig(cfg)}, nil
}

// NewReaderWithAPI builds a Reader over a caller-supplied API, for tests.
func NewReaderWithAPI(api API) (*Reader, error) {
	if api == nil {
		return nil, fmt.Errorf("%w: API is required", ErrConfiguration)
	}
	return &Reader{api: api}, nil
}

// Filter reads one bounded page of events from logGroup matching q.
func (r *Reader) Filter(ctx context.Context, logGroup string, q Query) (Result, error) {
	if logGroup == "" {
		return Result{}, fmt.Errorf("%w: log group is required", ErrInvalidQuery)
	}
	if q.Start.IsZero() || q.End.IsZero() || !q.Start.Before(q.End) {
		return Result{}, fmt.Errorf("%w: start must be before end, and both are required", ErrInvalidQuery)
	}
	if q.End.Sub(q.Start) > maxWindow {
		return Result{}, fmt.Errorf("%w: window exceeds %s", ErrInvalidQuery, maxWindow)
	}
	if len(q.FilterPattern) > maxFilterPattern {
		return Result{}, fmt.Errorf("%w: filter pattern too long", ErrInvalidQuery)
	}
	if len(q.NextToken) > maxNextToken {
		return Result{}, fmt.Errorf("%w: continuation token too long", ErrInvalidQuery)
	}
	limit := q.Limit
	if limit <= 0 {
		limit = defaultLimit
	}
	if limit > maxLimit {
		limit = maxLimit
	}

	in := &cloudwatchlogs.FilterLogEventsInput{
		LogGroupName: aws.String(logGroup),
		StartTime:    aws.Int64(q.Start.UnixMilli()),
		EndTime:      aws.Int64(q.End.UnixMilli()),
		Limit:        aws.Int32(limit),
	}
	if q.FilterPattern != "" {
		in.FilterPattern = aws.String(q.FilterPattern)
	}
	if q.NextToken != "" {
		in.NextToken = aws.String(q.NextToken)
	}

	out, err := r.api.FilterLogEvents(ctx, in)
	if err != nil {
		return Result{}, fmt.Errorf("%w: querying CloudWatch Logs failed", ErrUnavailable)
	}

	res := Result{Events: make([]Event, 0, len(out.Events))}
	for _, e := range out.Events {
		ev := Event{Message: aws.ToString(e.Message), LogStreamName: aws.ToString(e.LogStreamName)}
		if e.Timestamp != nil {
			ev.Timestamp = time.UnixMilli(*e.Timestamp).UTC()
		}
		res.Events = append(res.Events, ev)
	}
	if out.NextToken != nil {
		res.NextToken = *out.NextToken
	}
	return res, nil
}
