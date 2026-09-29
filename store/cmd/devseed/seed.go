// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"time"

	cp "github.com/conductorone/apphub/internal/controlplane"
)

type seeder struct {
	repo   cp.Repository
	target cp.TargetPolicy
	now    time.Time
	// users are the demo users' IDs, in demoUsers order.
	users []string
	// owner is the signed-in user's ID.
	owner string
}

func (s *seeder) seed(ctx context.Context, ownerEmail string, out io.Writer) error {
	owner, err := s.findUser(ctx, ownerEmail)
	if err != nil {
		return err
	}
	s.owner = owner

	users, err := s.seedUsers(ctx)
	if err != nil {
		return err
	}
	apps := 0
	for i, app := range demoApps {
		created, err := s.seedApplication(ctx, i, app)
		if err != nil {
			return fmt.Errorf("seed %q: %w", app.name, err)
		}
		if created {
			apps++
		}
	}
	_, err = fmt.Fprintf(out, "seeded %d user(s), %d application(s); %d applications in catalog\n", users, apps, len(demoApps))
	return err
}

// findUser resolves the signed-in account the demo applications are shared
// with. Sign in once before seeding so this record exists.
func (s *seeder) findUser(ctx context.Context, email string) (string, error) {
	cursor := ""
	for {
		page, err := s.repo.Query(ctx, cp.Query{Kind: cp.UserKind, Limit: 100, Cursor: cursor})
		if err != nil {
			return "", fmt.Errorf("list users: %w", err)
		}
		for _, r := range page.Records {
			u, err := cp.Decode[cp.User](r)
			if err == nil && u.Email == email {
				return u.ID, nil
			}
		}
		if page.Cursor == "" {
			return "", fmt.Errorf("no user with email %q; sign in to the local portal once, then seed", email)
		}
		cursor = page.Cursor
	}
}

func (s *seeder) seedUsers(ctx context.Context) (int, error) {
	created := 0
	for i, u := range demoUsers {
		email := u.email + "@" + demoDomain
		id := stableID("user:" + email)
		s.users = append(s.users, id)
		rng := rngFor("user:" + email)
		joined := s.now.Add(-days(rng, 60, 240))
		lastSeen := s.now.Add(-time.Duration(i*7+rng.IntN(300)) * time.Hour / 3)
		user := cp.User{ID: id, Email: email, Name: u.name, CreatedAt: joined, UpdatedAt: lastSeen}
		ok, err := s.createIfAbsent(ctx, id, "user.create", "user:"+id, cp.RecordID{Kind: cp.UserKind, ID: id}, user)
		if err != nil {
			return created, fmt.Errorf("seed user %s: %w", email, err)
		}
		if ok {
			created++
		}
	}
	return created, nil
}

// createIfAbsent writes one new record, reporting false if it already exists.
func (s *seeder) createIfAbsent(ctx context.Context, actor, action, auditTarget string, id cp.RecordID, value any) (bool, error) {
	_, err := s.repo.Read(ctx, id)
	if err == nil {
		return false, nil
	}
	if !errors.Is(err, cp.ErrNotFound) {
		return false, err
	}
	m, err := newRecord(id, value)
	if err != nil {
		return false, err
	}
	return true, s.repo.Commit(cp.WithAuditContext(ctx, actor, action, auditTarget), []cp.Mutation{m})
}

func newRecord(id cp.RecordID, value any) (cp.Mutation, error) {
	r, err := cp.Encode(id, 1, value)
	if err != nil {
		return cp.Mutation{}, fmt.Errorf("encode %s %s: %w", id.Kind, id.ID, err)
	}
	return cp.Mutation{Record: r}, nil
}

// stableID derives a UUID-shaped ID from a name, so reseeding finds the same
// records instead of adding duplicates.
func stableID(name string) string {
	sum := sha256.Sum256([]byte("apphub-devseed:" + name))
	sum[6] = (sum[6] & 0x0f) | 0x40
	sum[8] = (sum[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
}

// rngFor returns a generator seeded by name, so each record's details are the
// same on every run.
func rngFor(name string) *rand.Rand {
	sum := sha256.Sum256([]byte(name))
	return rand.New(rand.NewPCG(binary.BigEndian.Uint64(sum[0:8]), binary.BigEndian.Uint64(sum[8:16]))) //nolint:gosec // G404: reproducible demo data, not a secret
}

func days(rng *rand.Rand, lo, hi int) time.Duration {
	return time.Duration(lo*24+rng.IntN((hi-lo)*24)) * time.Hour
}

func hexString(rng *rand.Rand, n int) string {
	const digits = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = digits[rng.IntN(len(digits))]
	}
	return string(b)
}
