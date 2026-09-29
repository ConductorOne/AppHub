// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package credentials_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/conductorone/apphub/credentials"
)

// namedProvider is a provider whose ID is whatever a test says it is. That is the
// point: CredentialProvider.ID returns a string, so an ID is text this repository
// did not author, however much a comment would like it to be a registry constant.
type namedProvider struct{ id string }

func (p namedProvider) ID() string   { return p.id }
func (p namedProvider) Name() string { return "named" }
func (p namedProvider) CreateCredential(context.Context, credentials.CreateRequest) (*credentials.CreateResult, error) {
	return nil, errors.New("not implemented")
}
func (p namedProvider) RevokeCredential(context.Context, string, credentials.Metadata) error {
	return errors.New("not implemented")
}
func (p namedProvider) GetCredentialStatus(context.Context, string, credentials.Metadata) (credentials.CredentialStatus, error) {
	return credentials.CredentialStatusUnknown, errors.New("not implemented")
}
func (p namedProvider) SupportsDynamic() bool { return false }

// TestRegisterRefusesADuplicateWithoutNamingIt.
//
// The first version of this error formatted p.ID(), on the reasoning that a
// registry key is ours. Review drove a sentinel through ID and read it back out,
// which is the same defect CreateNotDeliveredError exists to prevent, at a second
// site. The information an operator needs is still here; it is reached by asking.
func TestRegisterRefusesADuplicateWithoutNamingIt(t *testing.T) {
	const id = "id-chosen-by-an-adopters-provider"
	r := credentials.NewProviderRegistry()
	if err := r.Register(namedProvider{id: id}); err != nil {
		t.Fatalf("first Register: %v", err)
	}

	err := r.Register(namedProvider{id: id})
	if err == nil {
		t.Fatal("a duplicate ID was accepted")
	}
	if !errors.Is(err, credentials.ErrDuplicateProvider) {
		t.Errorf("errors.Is did not match ErrDuplicateProvider: %v", err)
	}

	var dup *credentials.DuplicateProviderError
	if !errors.As(fmt.Errorf("wrapped: %w", err), &dup) {
		t.Fatal("errors.As did not find the type through a wrap")
	}
	if got := credentials.RevealForeign(dup.ProviderID()); got != id {
		t.Errorf("RevealForeign(ProviderID()) = %q, want the rejected ID", got)
	}
	if dup.Registered() != 1 {
		t.Errorf("Registered() = %d, want 1", dup.Registered())
	}

	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Error("m", slog.Any("err", err))
	for name, got := range map[string]string{
		"%v":       fmt.Sprintf("%v", err),
		"%+v":      fmt.Sprintf("%+v", err),
		"%#v":      fmt.Sprintf("%#v", err),
		"%q":       fmt.Sprintf("%q", err),
		"%s":       fmt.Sprintf("%s", err),
		"Error":    err.Error(),
		"GoString": dup.GoString(),
		"LogValue": fmt.Sprintf("%v", dup.LogValue()),
		"wrapped":  fmt.Errorf("outer: %w", err).Error(),
		"in a map": fmt.Sprintf("%v", map[string]error{"k": err}),
		"slog":     buf.String(),
	} {
		if strings.Contains(got, id) {
			t.Errorf("%s rendered the rejected ID: %s", name, got)
		}
	}

	// The count is the one piece of context the message may carry, and it is what
	// distinguishes "the wiring ran twice" from "two providers want one name".
	if !strings.Contains(err.Error(), "1") {
		t.Errorf("the message does not carry the count: %s", err.Error())
	}
	if !strings.Contains(err.Error(), "ProviderID") {
		t.Errorf("the message does not say where the ID can be found: %s", err.Error())
	}

	// The refusal must leave the first registration intact: a failed Register that
	// had overwritten the incumbent would be worse than one that overwrote openly.
	got, ok := r.Get(id)
	if !ok {
		t.Fatal("the incumbent is gone")
	}
	if got.Name() != "named" || len(r.List()) != 1 {
		t.Errorf("registry holds %d providers", len(r.List()))
	}
}
