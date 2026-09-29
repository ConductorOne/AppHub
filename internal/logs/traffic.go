// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package logs

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
)

// trafficQuery counts ingress access-log lines per Traefik service, UTC hour
// and status class. Traefik's JSON access log carries ServiceName (the
// service label AppHub writes on each application's ECS service, suffixed
// with "@<provider>") and DownstreamStatus. Lines without a ServiceName are
// Traefik's own logs or unrouted requests and are not anyone's traffic.
const trafficQuery = `filter ispresent(ServiceName) and ServiceName != "" and ispresent(DownstreamStatus)
| stats count(*) as requests, min(@timestamp) as first, max(@timestamp) as last by bin(1h) as hour, ServiceName, floor(DownstreamStatus / 100) as class
| limit 10000`

// trafficPoll is how often a running query is checked, and trafficTimeout
// how long one is allowed before it is stopped.
const (
	trafficPoll    = 2 * time.Second
	trafficTimeout = 2 * time.Minute
)

// ServiceHour is one Traefik service's requests of one status class in one
// UTC hour.
type ServiceHour struct {
	// Service is the Traefik service name without its "@provider" suffix.
	Service  string
	Hour     time.Time
	Class    int
	Requests int64
	First    time.Time
	Last     time.Time
}

// InsightsAPI is the CloudWatch Logs Insights operations [TrafficReader]
// calls, satisfied by *cloudwatchlogs.Client.
type InsightsAPI interface {
	StartQuery(ctx context.Context, in *cloudwatchlogs.StartQueryInput, opts ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StartQueryOutput, error)
	GetQueryResults(ctx context.Context, in *cloudwatchlogs.GetQueryResultsInput, opts ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetQueryResultsOutput, error)
	StopQuery(ctx context.Context, in *cloudwatchlogs.StopQueryInput, opts ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StopQueryOutput, error)
}

// TrafficReader counts requests per ingress service from one access-log group.
type TrafficReader struct {
	api      InsightsAPI
	logGroup string
	poll     time.Duration
}

// NewTrafficReader loads ambient AWS credentials for region.
func NewTrafficReader(ctx context.Context, region, logGroup string) (*TrafficReader, error) {
	if region == "" {
		return nil, fmt.Errorf("%w: region is required", ErrConfiguration)
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("%w: AWS configuration could not be loaded", ErrConfiguration)
	}
	return NewTrafficReaderWithAPI(cloudwatchlogs.NewFromConfig(cfg), logGroup)
}

// NewTrafficReaderWithAPI builds a TrafficReader over a caller-supplied API, for tests.
func NewTrafficReaderWithAPI(api InsightsAPI, logGroup string) (*TrafficReader, error) {
	if api == nil {
		return nil, fmt.Errorf("%w: API is required", ErrConfiguration)
	}
	if strings.TrimSpace(logGroup) == "" {
		return nil, fmt.Errorf("%w: log group is required", ErrConfiguration)
	}
	return &TrafficReader{api: api, logGroup: logGroup, poll: trafficPoll}, nil
}

// Hourly counts requests in [start, end), which must be whole UTC hours.
func (r *TrafficReader) Hourly(ctx context.Context, start, end time.Time) ([]ServiceHour, error) {
	if !start.Before(end) || !start.Equal(start.Truncate(time.Hour)) || !end.Equal(end.Truncate(time.Hour)) {
		return nil, fmt.Errorf("%w: the window must be whole hours with start before end", ErrInvalidQuery)
	}
	started, err := r.api.StartQuery(ctx, &cloudwatchlogs.StartQueryInput{
		LogGroupName: aws.String(r.logGroup),
		QueryString:  aws.String(trafficQuery),
		StartTime:    aws.Int64(start.Unix()),
		EndTime:      aws.Int64(end.Unix() - 1),
	})
	if err != nil || started == nil || started.QueryId == nil {
		return nil, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, trafficTimeout)
	defer cancel()
	for {
		out, err := r.api.GetQueryResults(ctx, &cloudwatchlogs.GetQueryResultsInput{QueryId: started.QueryId})
		if err != nil || out == nil {
			r.stop(started.QueryId)
			return nil, ErrUnavailable
		}
		switch out.Status {
		case cwtypes.QueryStatusComplete:
			return parseTraffic(out.Results), nil
		case cwtypes.QueryStatusFailed, cwtypes.QueryStatusCancelled, cwtypes.QueryStatusTimeout:
			return nil, ErrUnavailable
		}
		select {
		case <-ctx.Done():
			r.stop(started.QueryId)
			return nil, ErrUnavailable
		case <-time.After(r.poll):
		}
	}
}

// stop abandons a query on a fresh context: the caller's is usually the one
// that just expired.
func (r *TrafficReader) stop(id *string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _ = r.api.StopQuery(ctx, &cloudwatchlogs.StopQueryInput{QueryId: id})
}

// insightsTime is the layout Insights renders @timestamp and bin() values in.
const insightsTime = "2006-01-02 15:04:05.000"

// parseTraffic keeps only well-formed rows. A malformed row is skipped rather
// than failing the batch: it is one service-hour, and the rest are still true.
func parseTraffic(rows [][]cwtypes.ResultField) []ServiceHour {
	var out []ServiceHour
	for _, row := range rows {
		fields := map[string]string{}
		for _, f := range row {
			fields[aws.ToString(f.Field)] = aws.ToString(f.Value)
		}
		service, _, _ := strings.Cut(fields["ServiceName"], "@")
		hour, errHour := time.Parse(insightsTime, fields["hour"])
		class, errClass := strconv.ParseFloat(fields["class"], 64)
		requests, errRequests := strconv.ParseInt(fields["requests"], 10, 64)
		if service == "" || errHour != nil || errClass != nil || errRequests != nil || requests <= 0 {
			continue
		}
		first, _ := time.Parse(insightsTime, fields["first"])
		last, _ := time.Parse(insightsTime, fields["last"])
		out = append(out, ServiceHour{Service: service, Hour: hour.UTC(), Class: int(class), Requests: requests, First: first.UTC(), Last: last.UTC()})
	}
	return out
}
