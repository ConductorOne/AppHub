// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"log/slog"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/conductorone/apphub/credentials"
	"github.com/conductorone/apphub/internal/reachable"
)

// This file is the class fixture for the invariant the credentials packages hold:
//
//	No error returned by this package contains any text that did not come from a
//	constant here, a numeric count, or a Go type name. No rendering of a result
//	contains credential material.
//
// # Why it is here and not in internal/errhygiene
//
// internal/errhygiene states that invariant over five packages and derives their
// exported surface from go/types, which is the better construction and the one to
// prefer. It cannot reach this package, and the reason is structural rather than
// convenience: the AWS clients this provider calls are behind unexported
// interfaces -- store/dynamo.go's fence, applied here for the same reason -- so an
// external test can only build a provider over real clients, and driving
// CreateCredential through one would attempt a real STS call. A fixture that
// cannot drive the vend paths cannot check them.
//
// So the fixture is in-package, and it keeps errhygiene's two disciplines: the
// population is derived rather than listed, and an input it cannot classify is a
// failure rather than an absence.
//
// # Why the reflection walk is not reimplemented here too
//
// The seam above is about DRIVING: reaching CreateCredential needs real client
// types, and only in-package code can build them without a real STS call.
// Reading what a returned value exposes to reflection needs none of that --
// reflect.Value operates on an any, whatever package it came from, so the walk
// itself has no reason to be local.
//
// USOSS-75 found it had been made local anyway, and it had already drifted from
// internal/reachable, the shared answer to the same question (USOSS-46): this
// package's own walk read a byte slice to its Length, and a one-byte view (len
// 1) into a backing array whose sentinel sat past index 0 -- reachable by
// reflection through Value.Slice(0, Cap()), no unsafe required -- walked clean.
// internal/reachable reads to Capacity for exactly this reason and would have
// caught it. Two instruments over one question, never compared, with the
// weaker one standing where a reader assumes the stronger.
//
// So this file drives, and internal/reachable.Walk reads. There is one
// implementation of "what is reachable from a value" and this package does not
// have its own copy of it. TestTheHygieneFixtureCanFail plants the exact miss
// above as its control.
// # What that does not buy back
//
// Keeping the two disciplines closes the derivation gap, not the other one.
// USOSS-59 measured what a shared, independently-authored fixture catches that
// a subject's own does not: internal/errhygiene's differential check failed on
// a mutation in credentials -- a package that does join it -- while `go test
// ./credentials` stayed green. This file is written by this package's own
// author, against this package's own model of its vend paths, and a
// systematic gap in that model is exactly the shape this file cannot see
// either. That is a real cost, not a nominal one, and exporting stsAPI/iamAPI
// to pay it down was considered and declined -- see docs/decisions/ for why
// the fence outweighs it.

// Sentinels, one per input position, so that a leak names where it came from
// rather than only that there was one.
const (
	sentinelName      = "SENTINEL-credential-name"
	sentinelRequester = "SENTINEL-requester-id"
	sentinelType      = "SENTINEL-requester-type"
	sentinelMetadata  = "SENTINEL-metadata-value"
	sentinelHandle    = "SENTINEL-platform-key-id"
	sentinelAWS       = "SENTINEL-from-the-aws-response"
	sentinelMaterial  = "SENTINEL-credential-material"
	sentinelToken     = "SENTINEL-web-identity-token"
	sentinelConfig    = "SENTINEL configuration value"
)

func allSentinels() []string {
	return []string{
		sentinelName, sentinelRequester, sentinelType, sentinelMetadata,
		sentinelHandle, sentinelAWS, sentinelMaterial, sentinelToken, sentinelConfig,
	}
}

// renderEveryWay turns a value into text every way this repository can be read.
//
// The verb space is enumerated rather than chosen from, which is the lesson
// USOSS-53 paid 462 leaking paths for: a hand-picked set of verbs tests the verbs
// somebody thought of, and the leak lives in the complement. Every single-letter
// verb, with every flag, bare and embedded in a struct -- because a value that
// redacts itself standalone can still be printed field by field inside something
// else.
func renderEveryWay(t *testing.T, v any) map[string]string {
	t.Helper()
	out := map[string]string{}
	if v == nil {
		return out
	}
	verbs := []rune{}
	for c := 'a'; c <= 'z'; c++ {
		verbs = append(verbs, c)
	}
	for c := 'A'; c <= 'Z'; c++ {
		verbs = append(verbs, c)
	}
	flags := []string{"", "+", "#", " ", "-", "0", "+#"}
	type wrapper struct{ Value any }
	for _, verb := range verbs {
		for _, flag := range flags {
			format := "%" + flag + string(verb)
			out[format] = fmt.Sprintf(format, v)
			out["struct "+format] = fmt.Sprintf(format, wrapper{Value: v})
		}
	}
	if e, ok := v.(error); ok {
		out["Error()"] = e.Error()
	}
	if s, ok := v.(fmt.Stringer); ok {
		out["String()"] = s.String()
	}
	if b, err := json.Marshal(v); err == nil {
		out["json"] = string(b)
	}
	// gob panics rather than erroring on some inputs -- a nil pointer inside an
	// interface among them -- so the recover is not defensive noise: without it a
	// fixture that drives a nil result takes the test binary down and every
	// assertion after it is never made.
	func() {
		defer func() { _ = recover() }()
		var gobbed bytes.Buffer
		if err := gob.NewEncoder(&gobbed).Encode(v); err == nil {
			out["gob"] = gobbed.String()
		}
	}()
	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("rendered", slog.Any("value", v))
	out["slog json"] = logged.String()
	logged.Reset()
	slog.New(slog.NewTextHandler(&logged, nil)).Info("rendered", slog.Any("value", v))
	out["slog text"] = logged.String()
	return out
}

// assertNoSentinel fails if any rendering or reachable slot of v holds text.
//
// The reachable slot uses internal/reachable.Walk rather than a local
// reflection walk -- see the file doc comment's "why the reflection walk is
// not reimplemented here too" for what happened when this package kept its
// own copy.
func assertNoSentinel(t *testing.T, what string, v any, forbidden []string) {
	t.Helper()
	if isNilValue(v) {
		return
	}
	for how, text := range renderEveryWay(t, v) {
		for _, s := range forbidden {
			if strings.Contains(text, s) {
				t.Errorf("%s rendered with %s contains %q: %s", what, how, s, elide(text))
			}
		}
	}
	res, err := reachable.Walk(v)
	if err != nil {
		t.Fatalf("%s: reachable.Walk: %v", what, err)
	}
	for _, b := range res.Blobs {
		text := string(b.Bytes)
		for _, s := range forbidden {
			if strings.Contains(text, s) {
				t.Errorf("%s has %s reachable at %s", what, s, b.Path)
			}
		}
	}
}

// isNilValue reports whether v is nil, including a typed nil inside an interface.
//
// A plain v == nil misses (*credentials.CreateResult)(nil), which is exactly what a
// driver returns alongside an error. Rendering one is not a check of anything and
// gob panics on it.
func isNilValue(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return rv.IsNil()
	default:
		return false
	}
}

// elide bounds a failure message. A gob dump of a masked secret is kilobytes of
// noise, and a failure nobody can read is a failure people stop reading.
func elide(text string) string {
	const limit = 240
	if len(text) <= limit {
		return text
	}
	return text[:limit] + "... (" + fmt.Sprint(len(text)) + " bytes)"
}

// driver drives one exported callable with sentinels in every input it takes, or
// records why it is not driven.
type driver struct {
	// Run returns every value the callable produced.
	Run func(t *testing.T) []any
	// Why is the justification for a callable deliberately not driven. Exactly one
	// of Run and Why is set; a callable with neither fails the accounting.
	Why string
}

// drivers is the set of exported callables and what drives each.
//
// Keyed the way the accounting below names them, so a callable added to this
// package fails TestTheExportedSurfaceIsAccountedFor until it appears here.
var drivers = map[string]driver{
	"NewProvider": {Run: func(*testing.T) []any {
		cfg := fullConfig()
		cfg.Region = sentinelConfig
		_, err := NewProvider(cfg, nil, nil)
		out := []any{err}
		cfg = fullConfig()
		cfg.Static.PolicyARN = sentinelConfig
		_, err = NewProvider(cfg, nil, nil)
		out = append(out, err)
		// And the client-mismatch path, which names no value at all.
		_, err = NewProvider(fullConfig(), nil, nil)
		return append(out, err)
	}},

	"WithWebIdentity": {
		Why: "an Option stores a caller-supplied interface value on the provider and returns " +
			"nothing. Driving it and rendering what came back renders the CALLER's object, which " +
			"is what the first version of this driver did -- thirty-eight failures, every one of " +
			"them the test fake holding its own token in a plain string. What this package does " +
			"with that value, including failing to mint a token and refusing a nil source, is " +
			"driven by Provider.CreateCredential here and asserted behaviourally by " +
			"TestWebIdentityAndAssumeRoleDoNotFallBackToEachOther and " +
			"TestATokenSourceFailureIsNotAFallback.",
	},

	"Config.Validate": {Run: func(t *testing.T) []any {
		var out []any
		for _, f := range derivedConfigFields(t) {
			out = append(out, f.Set(fullConfig(), sentinelConfig).Validate())
		}
		return out
	}},

	"Provider.CreateCredential": {Run: func(t *testing.T) []any {
		var out []any
		// Every input position, and both credential types, and both an AWS
		// failure whose text carries a sentinel and a success whose material does.
		for _, tc := range []struct {
			name string
			run  func() (any, error)
		}{
			{"dynamic, AWS fails", func() (any, error) {
				h := newHarness(t, fullConfig())
				h.sts.fail = func(string, int) error {
					return withStatus(400, apiError{code: sentinelAWS})
				}
				return h.p.CreateCredential(context.Background(), sentinelRequest(credentials.CredentialTypeDynamic))
			}},
			{"dynamic, token source fails", func() (any, error) {
				h := newHarness(t, fullConfig()).withFakeTokens(sentinelToken)
				h.tok.err = errors.New(sentinelAWS)
				return h.p.CreateCredential(context.Background(), sentinelRequest(credentials.CredentialTypeDynamic))
			}},
			{"dynamic, presign fails", func() (any, error) {
				h := newHarness(t, fullConfig())
				h.pre.err = errors.New(sentinelAWS)
				return h.p.CreateCredential(context.Background(), sentinelRequest(credentials.CredentialTypeDynamic))
			}},
			{"dynamic, succeeds", func() (any, error) {
				h := newHarness(t, fullConfig()).withFakeTokens(sentinelToken)
				h.p.presign = newPresigner
				return h.p.CreateCredential(context.Background(), sentinelRequest(credentials.CredentialTypeDynamic))
			}},
			{"static, AWS fails", func() (any, error) {
				h := newHarness(t, fullConfig())
				h.iam.fail = func(string, int) error {
					return withStatus(409, apiError{code: sentinelAWS})
				}
				return h.p.CreateCredential(context.Background(), sentinelRequest(credentials.CredentialTypeStatic))
			}},
			{"static, cleanup also fails", func() (any, error) {
				h := newHarness(t, fullConfig())
				h.iam.fail = func(method string, _ int) error {
					if method == "CreateUser" {
						return nil
					}
					return withStatus(500, apiError{code: sentinelAWS})
				}
				return h.p.CreateCredential(context.Background(), sentinelRequest(credentials.CredentialTypeStatic))
			}},
			{"static, material cannot be delivered", func() (any, error) {
				h := newHarness(t, fullConfig())
				h.iam.credSecret = ""
				return h.p.CreateCredential(context.Background(), sentinelRequest(credentials.CredentialTypeStatic))
			}},
			{"static, succeeds with sentinel material", func() (any, error) {
				h := newHarness(t, fullConfig())
				h.iam.credSecret = sentinelMaterial
				return h.p.CreateCredential(context.Background(), sentinelRequest(credentials.CredentialTypeStatic))
			}},
			{"refused before AWS", func() (any, error) {
				h := newHarness(t, fullConfig())
				req := sentinelRequest(credentials.CredentialTypeStatic)
				req.RequestedScope = []string{sentinelMetadata}
				return h.p.CreateCredential(context.Background(), req)
			}},
		} {
			res, err := tc.run()
			out = append(out, err)
			if err == nil {
				out = append(out, res)
			}
		}
		return out
	}},

	"Provider.RevokeCredential": {Run: func(t *testing.T) []any {
		var out []any
		h := newHarness(t, fullConfig())
		out = append(out, h.p.RevokeCredential(context.Background(), sentinelHandle, sentinelMetadataBag()))
		out = append(out, h.p.RevokeCredential(context.Background(),
			staticHandle("iam-legal-"+strings.ReplaceAll(sentinelName, "-", "_"), "cred"), sentinelMetadataBag()))
		h2 := newHarness(t, fullConfig())
		h2.iam.fail = func(string, int) error { return withStatus(500, apiError{code: sentinelAWS}) }
		out = append(out, h2.p.RevokeCredential(context.Background(),
			staticHandle("iam-legal-user", "cred"), sentinelMetadataBag()))
		return out
	}},

	"Provider.GetCredentialStatus": {Run: func(t *testing.T) []any {
		var out []any
		h := newHarness(t, fullConfig())
		status, err := h.p.GetCredentialStatus(context.Background(), sentinelHandle, sentinelMetadataBag())
		out = append(out, err, status)
		h2 := newHarness(t, fullConfig())
		h2.iam.fail = func(string, int) error { return withStatus(500, apiError{code: sentinelAWS}) }
		status, err = h2.p.GetCredentialStatus(context.Background(),
			staticHandle("iam-legal-user", "cred"), sentinelMetadataBag())
		return append(out, err, status)
	}},

	"WebIdentityTokenSource.WebIdentityToken": {
		Why: "an interface method this package calls and does not implement. Its " +
			"implementation is the host's; what this package does with a token, and with a " +
			"failure to mint one, is driven by Provider.CreateCredential above.",
	},

	"Provider.ID":              {Run: func(t *testing.T) []any { return []any{newHarness(t, fullConfig()).p.ID()} }},
	"Provider.Name":            {Run: func(t *testing.T) []any { return []any{newHarness(t, fullConfig()).p.Name()} }},
	"Provider.SupportsDynamic": {Run: func(t *testing.T) []any { return []any{newHarness(t, fullConfig()).p.SupportsDynamic()} }},
	"Provider.Capabilities":    {Run: func(t *testing.T) []any { return []any{newHarness(t, fullConfig()).p.Capabilities()} }},
}

func sentinelRequest(kind credentials.CredentialType) credentials.CreateRequest {
	ttl := time.Hour
	if kind == credentials.CredentialTypeStatic {
		ttl = dayHours * time.Hour
	}
	return credentials.CreateRequest{
		Name:           sentinelName,
		CredentialType: kind,
		TTL:            ttl,
		Metadata:       sentinelMetadataBag(),
		RequesterID:    sentinelRequester,
		RequesterType:  sentinelType,
		IdempotencyKey: sentinelMetadata,
	}
}

func sentinelMetadataBag() credentials.Metadata {
	return credentials.Metadata{"region": sentinelMetadata, "role_arn": sentinelMetadata}
}

// TestNoErrorRendersForeignText is the invariant.
//
// Every driver's every returned value is rendered every way and walked, and no
// sentinel may appear -- with one exception, stated rather than assumed: a
// successful CreateResult's PlatformKeyID contains the sanitized credential name
// by design, because the handle is what names the IAM user a revoke has to find.
// So the name sentinel is permitted in a successful result and in nothing else.
func TestNoErrorRendersForeignText(t *testing.T) {
	t.Parallel()
	for name, d := range drivers {
		if d.Run == nil {
			continue
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			values := d.Run(t)
			if len(values) == 0 {
				t.Fatal("the driver produced nothing, so this ran over nothing")
			}
			drove := 0
			for _, v := range values {
				if isNilValue(v) {
					continue
				}
				drove++
				forbidden := allSentinels()
				if _, isResult := v.(*credentials.CreateResult); isResult {
					forbidden = withoutHandleAttribution(forbidden)
				}
				assertNoSentinel(t, fmt.Sprintf("%s -> %T", name, v), v, forbidden)
			}
			if drove == 0 {
				t.Fatal("every value the driver produced was nil; a candidate was never actually tried")
			}
		})
	}
}

// withoutHandleAttribution drops the two sentinels a successful handle carries by
// design, and only those two.
//
// A static handle names the IAM user, whose name is derived from the credential
// name; a dynamic handle names the role session, which is derived from the
// requester. Both are deliberate: the handle is the only thing a revoke and a
// CloudTrail row have to join on. Neither is credential material, and both are
// persisted in the platform's own record rather than sent anywhere.
//
// Writing this exemption is how the requester half was noticed. The first version
// dropped only the credential name, and thirty-seven cases failed at once -- all of
// them one class, all of them the dynamic result. Several failures at once are a
// statement about the instrument, and they were.
//
// The exemption is per returned value and not per type at any depth. An exemption
// that propagated through composition would hide the same text appearing inside
// something else, which is the mistake internal/errhygiene's ReachableExempt
// comment records.
func withoutHandleAttribution(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == sentinelName || s == sentinelRequester {
			continue
		}
		out = append(out, s)
	}
	return out
}

// TestTheHygieneFixtureCanFail is the control.
//
// Every assertion above is an absence, so a renderer that produced nothing, or a
// walk that visited nothing, would pass the whole file. This drives the same
// machinery over values that really do hold a sentinel and requires it to be
// found -- by the rendering matrix, by the reflection walk over an unexported
// field, and by the reflection walk over a one-byte slice view whose backing
// array holds the sentinel past its length. That last case is planted because
// this package's own walk missed exactly that shape until USOSS-75 deleted it
// in favor of internal/reachable, which reads to Capacity rather than Length --
// see the file doc comment's "why the reflection walk is not reimplemented
// here too".
func TestTheHygieneFixtureCanFail(t *testing.T) {
	t.Parallel()
	type holder struct {
		Exported   string
		unexported string
	}
	leaky := fmt.Errorf("wrapped: %w", errors.New(sentinelMaterial))

	rendered := renderEveryWay(t, leaky)
	if len(rendered) == 0 {
		t.Fatal("the rendering matrix produced nothing")
	}
	if !containsSentinel(rendered, sentinelMaterial) {
		t.Fatal("the rendering matrix did not find a sentinel in an error that plainly holds one")
	}

	walked, err := reachable.Walk(&holder{Exported: "fine", unexported: sentinelMaterial})
	if err != nil {
		t.Fatalf("reachable.Walk: %v", err)
	}
	if walked.Visited == 0 {
		t.Fatal("the reflection walk visited nothing")
	}
	if !blobsContainSentinel(walked, sentinelMaterial) {
		t.Fatal("the reflection walk did not reach an unexported field, which is the half " +
			"no list of verbs can cover")
	}

	// The USOSS-75 case: a one-byte slice view whose backing array holds the
	// sentinel past index 0. A walk bounded by Length reads only the view's
	// single byte and reports clean, which is what this package's own walk did
	// before it was deleted. Planted permanently so a regression -- swapping
	// the shared walk back out for a local, Length-bounded one -- fails this
	// file and not only internal/reachable's own suite.
	type oneByteView struct {
		view []byte // len 1; cap == len(sentinelMaterial); sentinel sits past index 0
	}
	backing := make([]byte, len(sentinelMaterial))
	copy(backing, sentinelMaterial)
	view := backing[:1]
	if len(view) != 1 || cap(view) != len(sentinelMaterial) {
		t.Fatalf("the capacity-hidden fixture is not the shape it claims: len=%d cap=%d",
			len(view), cap(view))
	}
	capacityHidden, err := reachable.Walk(&oneByteView{view: view})
	if err != nil {
		t.Fatalf("reachable.Walk: %v", err)
	}
	if !blobsContainSentinel(capacityHidden, sentinelMaterial) {
		t.Fatal("the reflection walk did not find a sentinel held past a one-byte view's length, " +
			"in its backing array's capacity -- the exact miss USOSS-75 found in this package's " +
			"former local walk")
	}

	// And the matrix has to be wide enough to matter. The number is logged rather
	// than asserted at a specific value, because the interesting property is that
	// the verb space is enumerated and not chosen from.
	t.Logf("the rendering matrix has %d entries", len(rendered))
	if len(rendered) < 300 {
		t.Fatalf("the rendering matrix has only %d entries; the verb space is not being enumerated",
			len(rendered))
	}
}

func containsSentinel(in map[string]string, sentinel string) bool {
	for _, v := range in {
		if strings.Contains(v, sentinel) {
			return true
		}
	}
	return false
}

// blobsContainSentinel reports whether any blob internal/reachable.Walk found
// contains sentinel.
func blobsContainSentinel(r reachable.Result, sentinel string) bool {
	for _, b := range r.Blobs {
		if strings.Contains(string(b.Bytes), sentinel) {
			return true
		}
	}
	return false
}

// TestTheExportedSurfaceIsAccountedFor derives the population and requires every
// member to be driven or named.
//
// The derivation is go/ast over this directory rather than go/types, and that is a
// weaker instrument with one known blind spot: it sees declarations, so it cannot
// see a method promoted into an exported type. TestNoExportedTypeEmbedsAnything
// closes that blind spot by construction instead of hoping -- if nothing embeds,
// nothing is promoted. Neither check covers the other and both are named here.
func TestTheExportedSurfaceIsAccountedFor(t *testing.T) {
	t.Parallel()
	found := map[string]bool{}
	for file, f := range sourceFiles(t) {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if !fn.Name.IsExported() {
				continue
			}
			key := fn.Name.Name
			if fn.Recv != nil && len(fn.Recv.List) == 1 {
				recv := receiverTypeName(fn.Recv.List[0].Type)
				if recv == "" {
					t.Fatalf("%s: cannot name the receiver of %s; this derivation cannot "+
						"classify it", file, fn.Name.Name)
				}
				if !ast.IsExported(recv) {
					// A method on an unexported type is not reachable from outside.
					continue
				}
				key = recv + "." + fn.Name.Name
			}
			found[key] = true
		}
		// Exported interface methods are exported callables too: a host implements
		// them, and this package's error text can reach one's caller.
		for _, decl := range f.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range gen.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok || !ts.Name.IsExported() {
					continue
				}
				iface, ok := ts.Type.(*ast.InterfaceType)
				if !ok {
					continue
				}
				for _, m := range iface.Methods.List {
					for _, n := range m.Names {
						if n.IsExported() {
							found[ts.Name.Name+"."+n.Name] = true
						}
					}
				}
			}
		}
	}
	if len(found) == 0 {
		t.Fatal("derived no exported callables")
	}
	var missing, stale []string
	for name := range found {
		d, ok := drivers[name]
		if !ok {
			missing = append(missing, name)
			continue
		}
		if d.Run == nil && d.Why == "" {
			missing = append(missing, name+" (neither driven nor justified)")
		}
	}
	for name := range drivers {
		if !found[name] {
			stale = append(stale, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) > 0 {
		t.Errorf("exported callables with no driver and no justification: %s",
			strings.Join(missing, ", "))
	}
	if len(stale) > 0 {
		t.Errorf("drivers for callables this package no longer exports: %s", strings.Join(stale, ", "))
	}
	t.Logf("accounted for %d exported callables", len(found))
}

func receiverTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return receiverTypeName(t.X)
	case *ast.IndexExpr:
		return receiverTypeName(t.X)
	default:
		return ""
	}
}

// TestNoExportedTypeEmbedsAnything closes the promotion blind spot of the
// derivation above.
//
// A syntax walk cannot see a method promoted from an embedded type, so the surface
// it derives would be short by exactly those. Rather than reaching for a stronger
// instrument that this package cannot afford -- go/types here means type-checking
// the AWS SDK from source -- the shape that would need one is forbidden. If a
// future change needs embedding, this test fails and whoever needs it has to
// upgrade the derivation rather than silently outgrow it.
func TestNoExportedTypeEmbedsAnything(t *testing.T) {
	t.Parallel()
	checked := 0
	for file, f := range sourceFiles(t) {
		for _, decl := range f.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range gen.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok || !ts.Name.IsExported() {
					continue
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					continue
				}
				checked++
				for _, field := range st.Fields.List {
					if len(field.Names) == 0 {
						t.Errorf("%s: exported type %s embeds a type; the surface derivation "+
							"cannot see promoted methods, so this needs a go/types derivation "+
							"rather than an embedded field", file, ts.Name.Name)
					}
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("found no exported struct types; this check ran over nothing")
	}
	t.Logf("checked %d exported struct types for embedding", checked)
}
