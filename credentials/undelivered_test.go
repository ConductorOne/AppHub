// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package credentials_test

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"text/template"

	"github.com/conductorone/apphub/credentials"
)

// handle is a stand-in for the worst realistic case: the value the upstream put
// in the field this error carries turned out to be a credential. Review produced
// exactly that against Datadog, which is why the handle now lives in a type
// instead of a format string.
const handle = "HANDLE-that-must-never-render"

// TestCreateNotDeliveredNeverRendersTheHandle walks every path a value escapes a
// Go program by accident. The list is the same one Secret is tested against,
// because the requirement is the same: this must fail closed rather than rely on
// call sites remembering.
func TestCreateNotDeliveredNeverRendersTheHandle(t *testing.T) {
	err := credentials.NewCreateNotDelivered("datadog", handle)

	var jsonBuf, textBuf bytes.Buffer
	slog.New(slog.NewJSONHandler(&jsonBuf, nil)).Error("vend failed", "err", err)
	slog.New(slog.NewTextHandler(&textBuf, nil)).Error("vend failed", "err", err)

	// SA9005 is correct and is the point: a struct with no exported fields and no
	// custom marshaller encodes to {}, which is exactly why the handle lives in an
	// unexported field. The test asserts the emptiness rather than assuming it.
	marshalled, marshalErr := json.Marshal(err) //nolint:staticcheck // SA9005: marshalling nothing is the property being verified
	if marshalErr != nil {
		marshalled = []byte("(marshal refused)")
	}

	var gobBuf bytes.Buffer
	if gobErr := gob.NewEncoder(&gobBuf).Encode(err); gobErr != nil {
		gobBuf.Reset()
		gobBuf.WriteString("(gob refused)")
	}

	renderings := map[string]string{
		"Error()":      err.Error(),
		"%v":           fmt.Sprintf("%v", err),
		"%+v":          fmt.Sprintf("%+v", err),
		"%#v":          fmt.Sprintf("%#v", err),
		"%s":           fmt.Sprintf("%s", err),
		"%q":           fmt.Sprintf("%q", err),
		"%x":           fmt.Sprintf("%x", err),
		"nested %v":    fmt.Sprintf("%v", struct{ E error }{err}),
		"nested %+v":   fmt.Sprintf("%+v", struct{ E error }{err}),
		"nested %#v":   fmt.Sprintf("%#v", struct{ E error }{err}),
		"slice":        fmt.Sprintf("%v", []error{err}),
		"map":          fmt.Sprintf("%v", map[string]error{"e": err}),
		"wrapped":      fmt.Errorf("issuing: %w", err).Error(),
		"joined":       errors.Join(errors.New("first"), err).Error(),
		"slog json":    jsonBuf.String(),
		"slog text":    textBuf.String(),
		"json.Marshal": string(marshalled),
		"gob":          gobBuf.String(),
	}

	for name, rendering := range renderings {
		if strings.Contains(rendering, handle) {
			t.Errorf("%s exposed the handle: %s", name, rendering)
		}
	}
}

// TestCreateNotDeliveredKeepsTheHandleReachable is the other requirement, and the
// reason dropping the handle is not an acceptable fix: it is the only record of a
// credential that exists upstream and must be revoked.
func TestCreateNotDeliveredKeepsTheHandleReachable(t *testing.T) {
	err := error(credentials.NewCreateNotDelivered("datadog", handle))
	wrapped := fmt.Errorf("issuing for application %s: %w", "app-1", err)

	if !errors.Is(wrapped, credentials.ErrCreateNotDelivered) {
		t.Error("errors.Is did not match through a wrap")
	}

	var nd *credentials.CreateNotDeliveredError
	if !errors.As(wrapped, &nd) {
		t.Fatal("errors.As did not find the type through a wrap")
	}
	if got := credentials.RevealForeign(nd.PlatformKeyID()); got != handle {
		t.Errorf("RevealForeign(PlatformKeyID()) = %q, want the handle", got)
	}
	if got := credentials.RevealForeign(nd.ProviderID()); got != "datadog" {
		t.Errorf("RevealForeign(ProviderID()) = %q", got)
	}
	// The accessors hand back a Foreign, so a template that walks the error by
	// name gets a placeholder rather than the value. That is the USOSS-43 shape.
	var b strings.Builder
	if err := template.Must(template.New("t").
		Parse(`{{.ProviderID}}|{{.PlatformKeyID}}`)).Execute(&b, nd); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if strings.Contains(b.String(), handle) || strings.Contains(b.String(), "datadog") {
		t.Errorf("a template reached the accessors: %q", b.String())
	}
}

// TestCreateNotDeliveredDoesNotNameTheProvider replaces a test that asserted the
// opposite.
//
// The earlier version required the message to carry the provider ID, on the
// reasoning that the ID is ours because it comes from a registry constant. Review
// falsified the premise rather than the code: CredentialProvider.ID returns a
// string and any provider may register, so the ID is caller-supplied text and a
// sentinel driven through NewCreateNotDelivered came back out of Error. The
// operator's need is real and is met by the accessor, which the message points at.
func TestCreateNotDeliveredDoesNotNameTheProvider(t *testing.T) {
	err := credentials.NewCreateNotDelivered("datadog", handle)
	msg := err.Error()
	if strings.Contains(msg, "datadog") {
		t.Errorf("error %q names the provider", msg)
	}
	if !strings.Contains(msg, "ProviderID") || !strings.Contains(msg, "PlatformKeyID") {
		t.Errorf("error %q does not say where the provider and the handle can be found", msg)
	}
	if got := credentials.RevealForeign(err.ProviderID()); got != "datadog" {
		t.Errorf("RevealForeign(ProviderID()) = %q, want the provider", got)
	}
}

// TestDescribeTypeRendersOnlyOurOwnConstants supports the stated invariant: no
// error from a provider carries text that arrived from outside the repository.
// CredentialType is a string type, so a value in it is caller-supplied text.
func TestDescribeTypeRendersOnlyOurOwnConstants(t *testing.T) {
	for _, tc := range []struct {
		In   credentials.CredentialType
		Want string
	}{
		{credentials.CredentialTypeDynamic, `"dynamic"`},
		{credentials.CredentialTypeStatic, `"static"`},
		{"", "no credential type"},
		{"SENTINEL-caller-supplied", "an unrecognized credential type"},
	} {
		if got := credentials.DescribeType(tc.In); got != tc.Want {
			t.Errorf("DescribeType(%q) = %q, want %q", tc.In, got, tc.Want)
		}
	}
}
