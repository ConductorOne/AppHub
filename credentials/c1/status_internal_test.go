// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package c1

// "Revoked is unreachable" as a derivation over its factors, not a product of
// chosen lists.
//
// # The finding this file exists to answer
//
// The negative -- GetCredentialStatus can never report revoked, because
// ConductorOne deletes a revoked credential rather than tombstoning it -- was
// first asserted over seven named responses, then over a 168-cell cross-product of
// fourteen status codes and twelve body shapes.
//
// Review defeated the 168-cell version, and the defeat is the interesting part:
// adding a decoded revokedAt field plus a real revoked mapping left it **green at
// revoked=0**, while an independently written hostile revokedAt response reached
// revoked immediately. The reviewer's phrase for what went wrong is the whole
// lesson: it was **a Cartesian product of chosen lists**. A cross-product feels
// exhaustive and is only exhaustive over the axes its author picked, and the axis
// that mattered was one I had not crossed. A product is a derivation over its
// factors *and a choice of factors*.
//
// And a 168-cell table is precisely the artefact that stops anyone looking
// further, which is what makes it worse than seven named cases rather than better.
//
// # So both factors are derived from the code
//
//   - The **body** axis comes from reflecting credentialBody, the client's own
//     decode target. Every JSON field the client can read contributes variants,
//     and the variants are chosen by the field's Go *type*. A field added to that
//     struct therefore enters this population without anyone editing this file --
//     including a revokedAt, which is why the reviewer's reproduction now fails.
//   - The **status** axis is the complete space, 100 through 599, rather than the
//     codes I thought were interesting. Phase A sweeps all of it and *derives*
//     which codes are behaviourally distinct; phase B crosses one representative
//     of each derived group against the full body product.
//
// This file is inside the package because the derivation needs credentialBody, and
// a fixture that reflects an unexported type is exactly where the invariant should
// live. It reads the package clock rather than pinning it, so the timestamps it
// generates are a day either side of now -- far enough that no plausible run time
// moves a cell across the boundary.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/conductorone/apphub/credentials"
)

const (
	derivedPrincipal  = "sp1111111111111111111111111"
	derivedCredential = "fixture-fixture-11111"
)

// statusTransport answers the token endpoint successfully and every API request
// with one fixed status and body.
type statusTransport struct {
	status int
	body   string
}

func (s statusTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.HasSuffix(req.URL.Path, tokenPath) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 ok",
			Header:     http.Header{},
			Body:       io.NopCloser(strings.NewReader(`{"access_token":"t","expires_in":3600}`)),
			Request:    req,
		}, nil
	}
	return &http.Response{
		StatusCode: s.status,
		Status:     fmt.Sprintf("%d upstream", s.status),
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader(s.body)),
		Request:    req,
	}, nil
}

func derivedProvider(t *testing.T, status int, body string) *Provider {
	t.Helper()
	client, err := NewClient(internalTestConfig(), Deps{Secrets: fixedSecrets{}, Transport: statusTransport{status: status, body: body}})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	p, err := NewProvider(client)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	return p
}

// jsonFieldsOf returns the JSON field names and Go types the client can decode off
// a credential response, read from the decode target itself.
func jsonFieldsOf(rt reflect.Type) []reflect.StructField {
	var out []reflect.StructField
	for i := range rt.NumField() {
		f := rt.Field(i)
		tag := f.Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func jsonName(f reflect.StructField) string {
	return strings.Split(f.Tag.Get("json"), ",")[0]
}

// variantsFor returns the raw JSON fragments this field takes in the population,
// chosen by the field's type rather than by its name.
//
// Type-driven is what makes the derivation grow correctly: a new *time.Time field
// gets past, future and zero timestamps without anyone deciding it should, which is
// exactly the case that defeated the previous version.
func variantsFor(f reflect.StructField, past, future time.Time) map[string]variant {
	v := map[string]variant{"absent": {WellTyped: true}}
	switch f.Type {
	case reflect.TypeOf(""):
		v["valid"] = variant{`"` + plausibleString(f) + `"`, true}
		v["empty"] = variant{`""`, true}
		v["hostile"] = variant{`"../../elsewhere"`, true}
		v["wrong type"] = variant{`12345`, false}
	case reflect.TypeOf((*time.Time)(nil)):
		v["far past"] = variant{`"` + past.Format(time.RFC3339) + `"`, true}
		v["far future"] = variant{`"` + future.Format(time.RFC3339) + `"`, true}
		v["zero time"] = variant{`"0001-01-01T00:00:00Z"`, true}
		v["null"] = variant{`null`, true}
		v["unparseable"] = variant{`"not a timestamp"`, false}
	case reflect.TypeOf([]string(nil)):
		v["one"] = variant{`["roleA"]`, true}
		v["empty"] = variant{`[]`, true}
		v["null"] = variant{`null`, true}
		v["wrong type"] = variant{`"roleA"`, false}
	case reflect.TypeOf(false):
		v["true"] = variant{`true`, true}
		v["false"] = variant{`false`, true}
	default:
		// A field whose type this derivation does not know how to vary must fail
		// loudly rather than silently contributing one shape. A skip here is the
		// bypass: it is how a revokedAt of some future type would slip in.
		v["UNKNOWN TYPE "+f.Type.String()] = variant{`null`, false}
	}
	return v
}

// variant is one value a field takes, plus whether it is well-typed for that
// field.
//
// WellTyped is recorded here rather than inferred from the variant's name, because
// inferring it from a name is a restatement of a grammar and this fixture exists
// because a restatement drifted. It is what lets
// TestEveryWellTypedBodyDecodes state a structural property instead of a ratio.
type variant struct {
	Frag      string
	WellTyped bool
}

// plausibleString is a value that will not be rejected for a reason unrelated to
// the field under test. The identity fields have to satisfy the handle grammar and
// the request's own principal, or the credential is refused before any status is
// computed and the cell measures nothing.
func plausibleString(f reflect.StructField) string {
	switch jsonName(f) {
	case "servicePrincipalId":
		return derivedPrincipal
	case "id":
		return derivedCredential
	default:
		return "plausible-value"
	}
}

// unknownTypeVariants reports the variant keys that mean "this derivation does not
// know this type", so a test can fail on them rather than quietly proceeding.
func unknownTypeVariants(v map[string]variant) []string {
	var out []string
	for k := range v {
		if strings.HasPrefix(k, "UNKNOWN TYPE ") {
			out = append(out, k)
		}
	}
	return out
}

func TestTheDerivedBodyPopulationKnowsEveryDecodableField(t *testing.T) {
	// The cross-check that makes this a derivation. Every field the client decodes
	// must have variants chosen for its type; a field whose type is unrecognised
	// fails here rather than contributing a single null and being counted.
	fields := jsonFieldsOf(reflect.TypeOf(credentialBody{}))
	if len(fields) == 0 {
		t.Fatal("reflection found no decodable fields; the derivation is empty and every check over it would pass")
	}
	past, future := time.Now().Add(-24*time.Hour), time.Now().Add(24*time.Hour)

	total := 1
	for _, f := range fields {
		v := variantsFor(f, past, future)
		if unknown := unknownTypeVariants(v); len(unknown) > 0 {
			t.Errorf("credentialBody.%s is a %s, which variantsFor does not know how to vary: add a case, or the population covers it with one shape",
				f.Name, f.Type)
		}
		if len(v) < 2 {
			t.Errorf("credentialBody.%s has %d variant(s); a single variant is not a population", f.Name, len(v))
		}
		total *= len(v)
	}
	t.Logf("%d decodable field(s), %d body shapes derived from them", len(fields), total)
}

// derivedBodies returns the full Cartesian product over the reflected fields.
func derivedBodies(t *testing.T) map[string]derivedBody {
	t.Helper()
	fields := jsonFieldsOf(reflect.TypeOf(credentialBody{}))
	if len(fields) == 0 {
		t.Fatal("empty field derivation")
	}
	past, future := time.Now().Add(-24*time.Hour), time.Now().Add(24*time.Hour)

	type cell struct {
		name, frag string
		wellTyped  bool
	}
	combos := [][]cell{{}}
	for _, f := range fields {
		variants := variantsFor(f, past, future)
		keys := make([]string, 0, len(variants))
		for k := range variants {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		next := make([][]cell, 0, len(combos)*len(keys))
		for _, base := range combos {
			for _, k := range keys {
				frag := ""
				if variants[k].Frag != "" {
					frag = `"` + jsonName(f) + `":` + variants[k].Frag
				}
				next = append(next, append(append([]cell{}, base...),
					cell{f.Name + "=" + k, frag, variants[k].WellTyped}))
			}
		}
		combos = next
	}

	out := make(map[string]derivedBody, len(combos)+8)
	for _, combo := range combos {
		var names, frags []string
		wellTyped := true
		for _, c := range combo {
			names = append(names, c.name)
			if c.frag != "" {
				frags = append(frags, c.frag)
			}
			wellTyped = wellTyped && c.wellTyped
		}
		out[strings.Join(names, " ")] = derivedBody{
			Body:      `{"credential":{` + strings.Join(frags, ",") + `}}`,
			WellTyped: wellTyped,
		}
	}

	// Whole-response shapes, which are not field-driven and so are not derivable
	// from the struct. Named as the residual they are rather than folded in.
	for name, body := range map[string]string{
		"no credential key":  `{}`,
		"credential is null": `{"credential":null}`,
		"not JSON":           `nope`,
		"an array":           `[{"credential":{}}]`,
		"truncated":          `{"credential":`,
		"a bare string":      `{"credential":"a string where an object belongs"}`,
	} {
		out[name] = derivedBody{Body: body, WellTyped: false}
	}
	return out
}

// derivedBody is one generated response, plus whether every field in it is
// well-typed for the struct the client decodes into.
type derivedBody struct {
	Body      string
	WellTyped bool
}

func TestRevokedIsUnreachableOverTheDerivedPopulation(t *testing.T) {
	handle, err := FormatHandle(Ref{ServicePrincipalID: derivedPrincipal, CredentialID: derivedCredential})
	if err != nil {
		t.Fatalf("FormatHandle: %v", err)
	}
	canonical := `{"credential":{"id":"` + derivedCredential + `","servicePrincipalId":"` + derivedPrincipal +
		`","clientId":"c","expiresAt":"2099-01-01T00:00:00Z"}}`

	// --- Phase A: the complete status space, not a chosen list. -------------
	//
	// This derives which codes are behaviourally distinct instead of assuming it.
	groups := map[credentials.CredentialStatus][]int{}
	for code := 100; code <= 599; code++ {
		got, _ := derivedProvider(t, code, canonical).GetCredentialStatus(context.Background(), handle, nil)
		groups[got] = append(groups[got], code)
	}
	if len(groups) == 0 {
		t.Fatal("the status sweep produced no outcomes")
	}
	if n := len(groups[credentials.CredentialStatusRevoked]); n != 0 {
		t.Errorf("phase A: %d of 500 status codes reported revoked", n)
	}

	// One representative per derived group, so phase B's status axis is the
	// derivation's output rather than my opinion.
	var representatives []int
	for _, codes := range groups {
		sort.Ints(codes)
		representatives = append(representatives, codes[0])
		// And one from the middle, because a group's first member may be the only
		// one anybody ever thinks about.
		representatives = append(representatives, codes[len(codes)/2])
	}
	sort.Ints(representatives)

	// --- Phase B: those codes against the full derived body product. ---------
	bodies := derivedBodies(t)
	if len(bodies) == 0 {
		t.Fatal("empty body population")
	}

	seen := map[credentials.CredentialStatus]int{}
	var revoked []string
	checked := 0
	for _, code := range representatives {
		for name, b := range bodies {
			got, gotErr := derivedProvider(t, code, b.Body).GetCredentialStatus(context.Background(), handle, nil)
			switch got {
			case credentials.CredentialStatusActive,
				credentials.CredentialStatusExpired,
				credentials.CredentialStatusUnknown:
			case credentials.CredentialStatusRevoked:
				if len(revoked) < 3 {
					revoked = append(revoked, fmt.Sprintf("%d / %s", code, name))
				}
			default:
				t.Errorf("%d / %s: status %q is outside the enum (err=%v)", code, name, got, gotErr)
			}
			seen[got]++
			checked++
		}
	}

	if len(revoked) > 0 || seen[credentials.CredentialStatusRevoked] > 0 {
		t.Errorf("%d of %d derived combinations reported revoked, e.g. %v -- ConductorOne has no revoked-but-present state, so either the mapping changed or the upstream did",
			seen[credentials.CredentialStatusRevoked], checked, revoked)
	}
	// The positive halves, so the negative is not satisfied by a mapping that
	// answers unknown to everything.
	for _, must := range []credentials.CredentialStatus{
		credentials.CredentialStatusActive,
		credentials.CredentialStatusExpired,
		credentials.CredentialStatusUnknown,
	} {
		if seen[must] == 0 {
			t.Errorf("no combination in a population of %d produced %q", checked, must)
		}
	}
	t.Logf("phase A: 500 status codes -> %d distinct outcome(s); phase B: %d representative code(s) x %d derived bodies = %d cells (active=%d expired=%d unknown=%d revoked=%d)",
		len(groups), len(representatives), len(bodies), checked,
		seen[credentials.CredentialStatusActive], seen[credentials.CredentialStatusExpired],
		seen[credentials.CredentialStatusUnknown], seen[credentials.CredentialStatusRevoked])
}

func TestEveryWellTypedBodyDecodes(t *testing.T) {
	// A derivation emitting nothing but malformed JSON would report revoked=0
	// honestly and mean nothing, because every cell would fail to decode before any
	// status was computed. So the population needs a floor.
	//
	// The floor is structural rather than a ratio. An earlier version of this check
	// asserted that more than half the bodies decode, which is a threshold I chose
	// -- the same defect one level down from the one this file exists to fix. What
	// is asserted instead: **every** body all of whose field values are well-typed
	// must decode, and that set must be non-empty. Well-typedness is recorded on
	// the variant rather than inferred from its name.
	bodies := derivedBodies(t)
	wellTyped, failed := 0, 0
	var examples []string
	for name, b := range bodies {
		if !b.WellTyped {
			continue
		}
		wellTyped++
		var into getResponseBody
		if err := json.Unmarshal([]byte(b.Body), &into); err != nil {
			failed++
			if len(examples) < 3 {
				examples = append(examples, fmt.Sprintf("%s: %v", name, err))
			}
		}
	}
	if wellTyped == 0 {
		t.Fatal("no well-typed bodies were derived, so the population cannot exercise the mapping at all")
	}
	if failed != 0 {
		t.Errorf("%d of %d well-typed bodies failed to decode, e.g. %v", failed, wellTyped, examples)
	}
	t.Logf("%d of %d derived bodies are well-typed, and all of them decode", wellTyped, len(bodies))
}
