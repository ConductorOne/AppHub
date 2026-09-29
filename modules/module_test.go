// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package modules_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/conductorone/apphub/modules"
)

// exampleModule is what a real module looks like from the framework's side: it
// embeds BaseModule for the metadata, declares the interface it needs rather
// than importing a supplier for it, and takes that dependency in its
// constructor. Nothing in this file imports anything a module could not.
type exampleModule struct {
	modules.BaseModule
	sink resultSink
}

// resultSink is the narrow collaborator interface, owned by the consumer -- the
// pattern the package doc calls the load-bearing rule.
type resultSink interface {
	Record(ctx context.Context, userID string, note string) error
}

const exampleModuleID = "example"

func newExampleModule(sink resultSink) (*exampleModule, error) {
	if sink == nil {
		return nil, modules.Missing(exampleModuleID, "result sink")
	}
	return &exampleModule{
		BaseModule: modules.NewBaseModule(
			exampleModuleID,
			"Example",
			"Does an example thing",
			"science",
			"examples",
		),
		sink: sink,
	}, nil
}

func (m *exampleModule) Schema() *modules.JSONSchema {
	return &modules.JSONSchema{
		Type: "object",
		Properties: map[string]modules.JSONSchemaProperty{
			"target": {Type: "string", Description: "What to act on"},
			"spec":   {Type: "object", Description: "Structured, module-specific input"},
		},
		Required: []string{"target"},
	}
}

func (m *exampleModule) Validate(params map[string]any) error {
	if err := modules.ValidateDeclaredParams(m.Schema(), params); err != nil {
		return err
	}
	if _, ok := params["target"].(string); !ok {
		return errors.New("target is required and must be a string")
	}
	return nil
}

func (m *exampleModule) Execute(ctx context.Context, userID string, params map[string]any) (*modules.Result, error) {
	if err := m.Validate(params); err != nil {
		return nil, err
	}
	modules.ReportProgress(ctx, 50, "working")
	if err := m.sink.Record(ctx, userID, params["target"].(string)); err != nil {
		return nil, err
	}
	modules.ReportProgress(ctx, 100, "done")
	return &modules.Result{
		Success: true,
		Message: "ok",
		// Echoed back so the generality test can prove the parameter map carried
		// a structured value through untouched.
		Data: map[string]any{"spec": params["spec"]},
	}, nil
}

type recordingSink struct {
	notes []string
}

func (s *recordingSink) Record(_ context.Context, _ string, note string) error {
	s.notes = append(s.notes, note)
	return nil
}

// A module embedding BaseModule satisfies Module as a pointer. This assertion is
// the compile-time half of the contract: if the interface is ever narrowed or
// widened, this file stops building.
var _ modules.Module = (*exampleModule)(nil)

func TestBaseModuleSuppliesMetadata(t *testing.T) {
	t.Parallel()

	base := modules.NewBaseModule("id", "Name", "Description", "icon", "category")

	if got, want := base.ID(), "id"; got != want {
		t.Errorf("ID() = %q, want %q", got, want)
	}
	if got, want := base.Name(), "Name"; got != want {
		t.Errorf("Name() = %q, want %q", got, want)
	}
	if got, want := base.Description(), "Description"; got != want {
		t.Errorf("Description() = %q, want %q", got, want)
	}
	if got, want := base.Icon(), "icon"; got != want {
		t.Errorf("Icon() = %q, want %q", got, want)
	}
	if got, want := base.Category(), "category"; got != want {
		t.Errorf("Category() = %q, want %q", got, want)
	}
}

func TestConstructorFailsClosedOnMissingDependency(t *testing.T) {
	t.Parallel()

	m, err := newExampleModule(nil)
	if err == nil {
		t.Fatal("newExampleModule(nil) returned no error; a module must not be constructed without its dependencies")
	}
	if m != nil {
		t.Errorf("newExampleModule(nil) returned a module (%v) alongside its error", m)
	}
	if !errors.Is(err, modules.ErrNotConfigured) {
		t.Errorf("error %v does not match ErrNotConfigured", err)
	}
}

// TestExecuteCarriesStructuredParamsUnchanged is the generality check the
// interface has to keep passing: a capability whose inputs do not fit five flat
// strings nests a structured value under one key, and the framework neither
// inspects nor flattens it. Narrowing Execute to typed per-module parameters
// would break this, which is why the shape is a decision and not a detail.
func TestExecuteCarriesStructuredParamsUnchanged(t *testing.T) {
	t.Parallel()

	sink := &recordingSink{}
	m, err := newExampleModule(sink)
	if err != nil {
		t.Fatalf("newExampleModule: %v", err)
	}

	// Deliberately shaped like the rich, kind-specific input of a capability
	// outside the v1 set: nested maps, a list, mixed value types.
	spec := map[string]any{
		"kind": "agent",
		"size": "medium",
		"hibernation": map[string]any{
			"enabled":     true,
			"idleMinutes": 30,
		},
		"volumes": []any{"data", "cache"},
	}

	res, err := m.Execute(context.Background(), "user-1", map[string]any{
		"target": "thing",
		"spec":   spec,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !res.Success {
		t.Fatalf("Execute returned Success=false: %+v", res)
	}

	roundTripped, ok := res.Data["spec"].(map[string]any)
	if !ok {
		t.Fatalf("Data[spec] is %T, want map[string]any", res.Data["spec"])
	}
	hib, ok := roundTripped["hibernation"].(map[string]any)
	if !ok {
		t.Fatalf("spec[hibernation] is %T, want map[string]any", roundTripped["hibernation"])
	}
	if got, want := hib["idleMinutes"], 30; got != want {
		t.Errorf("nested value changed in transit: got %v, want %v", got, want)
	}
	if len(sink.notes) != 1 || sink.notes[0] != "thing" {
		t.Errorf("sink recorded %v, want [thing]", sink.notes)
	}
}

// partialModule fails after doing part of the work, and reports both: the error
// says it failed, the Result carries what exists. This is the shape the ported
// deploy module uses when it creates the function but cannot attach the load
// balancer, and it is why [modules.Module]'s Execute documents the two returns
// as independent.
type partialModule struct {
	modules.BaseModule
}

func newPartialModule() *partialModule {
	return &partialModule{BaseModule: modules.NewBaseModule("partial", "Partial", "", "", "examples")}
}

func (m *partialModule) Schema() *modules.JSONSchema { return &modules.JSONSchema{Type: "object"} }

func (m *partialModule) Validate(params map[string]any) error {
	return modules.ValidateDeclaredParams(m.Schema(), params)
}

func (m *partialModule) Execute(context.Context, string, map[string]any) (*modules.Result, error) {
	return &modules.Result{
			Success: false,
			Message: "function deployed but load balancer failed",
			Data:    map[string]any{"functionName": "f", "roleArn": "r"},
		},
		errors.New("load balancer deployment failed")
}

var _ modules.Module = (*partialModule)(nil)

// TestExecuteMayReturnBothResultAndError pins the contract a caller has to code
// against: a non-nil error does not mean the Result is absent or meaningless.
//
// It is a regression guard rather than a bug reproduction. The defect it answers
// was in a doc comment, which claimed a nil-Result-on-error convention the ported
// code does not obey, and prose has no failing test. What this pins is the
// behaviour the corrected comment describes, so a later change that enforces the
// invented convention -- nilling the Result out when err != nil, say, or
// asserting the pairing in a helper -- breaks a test instead of quietly
// discarding partial state.
func TestExecuteMayReturnBothResultAndError(t *testing.T) {
	t.Parallel()

	res, err := newPartialModule().Execute(context.Background(), "user-1", nil)

	if err == nil {
		t.Fatal("Execute returned no error; this module reports a failure")
	}
	if res == nil {
		t.Fatal("Execute returned a nil Result alongside its error, losing the partial state")
	}
	if res.Success {
		t.Error("Result.Success is true on a reported failure")
	}
	// The partial state is the whole point: it is what a caller needs to clean up
	// or resume, and it is what discarding the Result on error would lose.
	if got, want := res.Data["functionName"], "f"; got != want {
		t.Errorf("Data[functionName] = %v, want %v", got, want)
	}
	if got, want := res.Data["roleArn"], "r"; got != want {
		t.Errorf("Data[roleArn] = %v, want %v", got, want)
	}
}

// Success is the module's own statement, not a restatement of err == nil, so
// neither may be derived from the other. Registering the module and going back
// through the interface proves the framework does not normalise the pairing on
// the way through.
func TestSuccessIsNotDerivedFromError(t *testing.T) {
	t.Parallel()

	r := modules.NewRegistry()
	if err := r.Register(newPartialModule()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	m, ok := r.Get("partial")
	if !ok {
		t.Fatal("Get(partial) reported not found")
	}

	res, err := m.Execute(context.Background(), "user-1", nil)
	if err == nil || res == nil {
		t.Fatalf("Execute() = (%v, %v), want both non-nil", res, err)
	}
	if res.Message == "" {
		t.Error("the Result accompanying an error carries no message")
	}
}

// handledFailureModule reports an unsuccessful outcome with a nil error: the
// other off-diagonal from partialModule. The source does this too, computing
// Success from a rolled-up delivery status (announce/delivery.go:222-232), which
// is why Success cannot be read as a restatement of err == nil in either
// direction.
type handledFailureModule struct {
	modules.BaseModule
}

func newHandledFailureModule() *handledFailureModule {
	return &handledFailureModule{BaseModule: modules.NewBaseModule("handled", "Handled", "", "", "examples")}
}

func (m *handledFailureModule) Schema() *modules.JSONSchema {
	return &modules.JSONSchema{Type: "object"}
}

func (m *handledFailureModule) Validate(params map[string]any) error {
	return modules.ValidateDeclaredParams(m.Schema(), params)
}

func (m *handledFailureModule) Execute(context.Context, string, map[string]any) (*modules.Result, error) {
	return &modules.Result{Success: false, Message: "two of three channels failed"}, nil
}

var _ modules.Module = (*handledFailureModule)(nil)

func TestUnsuccessfulResultWithNilErrorIsValid(t *testing.T) {
	t.Parallel()

	res, err := newHandledFailureModule().Execute(context.Background(), "user-1", nil)
	if err != nil {
		t.Fatalf("Execute returned an error; this module reports its failure in the Result: %v", err)
	}
	if res == nil {
		t.Fatal("Execute returned no Result")
	}
	if res.Success {
		t.Error("Result.Success is true on a reported failure")
	}
	// A caller inferring success from err == nil would call this a success.
	if res.Message == "" {
		t.Error("an unsuccessful Result carries no message")
	}
}

// TestExecuteAcceptsAnEmptyUserID pins that userID is not required to be
// present. One of the source's five dispatch paths (cmd/job-runner/main.go:540)
// has no requester and passes "", so a module that assumed a non-empty userID --
// or a framework that rejected an empty one -- would break on that path. This is
// the executable half of the userID contract in [modules.Module]: the interface
// obliges nothing beyond identifying the requester when there is one.
func TestExecuteAcceptsAnEmptyUserID(t *testing.T) {
	t.Parallel()

	sink := &recordingSink{}
	m, err := newExampleModule(sink)
	if err != nil {
		t.Fatalf("newExampleModule: %v", err)
	}

	res, err := m.Execute(context.Background(), "", map[string]any{"target": "thing"})
	if err != nil {
		t.Fatalf("Execute with an empty userID: %v", err)
	}
	if !res.Success {
		t.Errorf("Execute with an empty userID returned Success=false: %+v", res)
	}
}

func TestResultJSONShape(t *testing.T) {
	t.Parallel()

	// Empty optional fields are omitted, so a minimal result does not serialise
	// keys a caller would have to ignore.
	got, err := json.Marshal(&modules.Result{Message: "no"})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if want := `{"success":false,"message":"no"}`; string(got) != want {
		t.Errorf("Marshal() = %s, want %s", got, want)
	}

	got, err = json.Marshal(&modules.Result{
		Success:   true,
		RequestID: "req-1",
		Message:   "yes",
		Data:      map[string]any{"k": "v"},
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if want := `{"success":true,"requestId":"req-1","message":"yes","data":{"k":"v"}}`; string(got) != want {
		t.Errorf("Marshal() = %s, want %s", got, want)
	}
}

func TestJSONSchemaPropertyDistinguishesZeroBoundFromAbsentBound(t *testing.T) {
	t.Parallel()

	zero := 0
	withBound, err := json.Marshal(modules.JSONSchemaProperty{Type: "integer", Minimum: &zero})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if want := `{"type":"integer","minimum":0}`; string(withBound) != want {
		t.Errorf("Marshal() = %s, want %s", withBound, want)
	}

	withoutBound, err := json.Marshal(modules.JSONSchemaProperty{Type: "integer"})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if want := `{"type":"integer"}`; string(withoutBound) != want {
		t.Errorf("Marshal() = %s, want %s", withoutBound, want)
	}
}
