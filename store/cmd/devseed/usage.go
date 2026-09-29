// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"math"
	"math/rand/v2"
	"time"

	cp "github.com/conductorone/apphub/internal/controlplane"
)

// usage fabricates hourly traffic for a routed application from its first
// successful deploy until now: busier on weekday working hours in US Pacific
// time, with a burst of server errors after a failed latest deploy.
func (s *seeder) usage(rng *rand.Rand, app demoApp, rec cp.ApplicationRecord, history []cp.DeploymentRecord) (cp.ApplicationUsageRecord, bool) {
	if len(rec.Application.Routes) == 0 || rec.LastSuccessfulDeploymentID == "" {
		return cp.ApplicationUsageRecord{}, false
	}
	var live time.Time
	for _, d := range history {
		if d.State == cp.Succeeded {
			live = d.FinishedAt
			break
		}
	}
	peak := 20 + rng.Float64()*140
	if app.public {
		peak = 400 + rng.Float64()*1600
	}
	var incident time.Time
	if app.scenario == failedLatest {
		incident = history[len(history)-1].CreatedAt
	}

	start := s.now.Add(-cp.UsageRetention)
	if live.After(start) {
		start = live
	}
	start = start.Truncate(time.Hour).Add(time.Hour)
	end := s.now.Truncate(time.Hour)
	pacific := time.FixedZone("PT", -7*60*60)
	traffic := cp.ApplicationUsageRecord{ID: rec.ID, CollectedAt: s.now}
	for hour := start; !hour.After(end); hour = hour.Add(time.Hour) {
		local := hour.In(pacific)
		load := 0.08 + 0.92*math.Max(0, math.Sin(math.Pi*float64(local.Hour()-6)/14))
		if local.Weekday() == time.Saturday || local.Weekday() == time.Sunday {
			load *= 0.35
		}
		if hour.Equal(end) {
			load *= float64(s.now.Minute()) / 60
		}
		requests := int64(peak * load * (0.8 + 0.4*rng.Float64()))
		if requests <= 0 {
			continue
		}
		b := cp.UsageBucket{Hour: hour, Requests: requests}
		b.Status5xx = int64(float64(requests) * 0.002 * rng.Float64())
		if !incident.IsZero() && !hour.Before(incident.Truncate(time.Hour)) && hour.Before(incident.Add(3*time.Hour)) {
			b.Status5xx = requests / 6
		}
		b.Status4xx = int64(float64(requests) * (0.01 + 0.03*rng.Float64()))
		b.Status3xx = int64(float64(requests) * 0.05 * rng.Float64())
		b.Status2xx = requests - b.Status5xx - b.Status4xx - b.Status3xx
		traffic.Buckets = append(traffic.Buckets, b)
	}
	if len(traffic.Buckets) == 0 {
		return cp.ApplicationUsageRecord{}, false
	}
	traffic.FirstRequestAt = traffic.Buckets[0].Hour.Add(time.Duration(rng.IntN(3600)) * time.Second)
	traffic.LastRequestAt = s.now.Add(-time.Duration(5+rng.IntN(90)) * time.Second)
	return traffic, true
}
