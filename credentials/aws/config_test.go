// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// This file holds the ticket's central property, stated over a derived population.
//
//	Every identifier this provider acts on is a configuration field with no
//	default, and an unset one is refused.
//
// The population is the field set of Config and the structs it points at, taken
// from the reflect type rather than from a list in this file. A field added later
// joins the enumeration without anybody remembering to add it, and a field whose
// kind this test cannot classify is a failure rather than a silent absence -- the
// case that makes an exhaustive-looking enumeration exhaustive over the wrong set.

// configField is one field of one config struct, named for a failure message.
type configField struct {
	// Path is "Static.PolicyARN".
	Path string
	// Set writes value into a copy of the full configuration and returns it.
	Set func(cfg Config, value string) Config
}

// derivedConfigFields walks Config by reflection.
//
// Two kinds are recognised. A string field is a required value. A pointer to a
// struct is the switch that decides whether a credential type is offered at all,
// so it is recursed into and separately checked by
// TestAnUnconfiguredCredentialTypeIsNotOffered. Anything else fails the
// derivation, loudly: a bool, an int or a slice would each need its own decision
// about what "unset" means, and guessing is how a field ends up with a default
// nobody chose.
func derivedConfigFields(t *testing.T) []configField {
	t.Helper()
	var out []configField
	walk(t, reflect.TypeOf(Config{}), nil, &out)
	if len(out) == 0 {
		t.Fatal("derived no configuration fields; a derivation that returns nothing passes every check over it")
	}
	return out
}

func walk(t *testing.T, typ reflect.Type, prefix []int, out *[]configField) {
	t.Helper()
	for i := range typ.NumField() {
		f := typ.Field(i)
		if !f.IsExported() {
			t.Fatalf("%s.%s is unexported; an operator cannot set it and this test cannot classify it",
				typ.Name(), f.Name)
		}
		path := append(append([]int(nil), prefix...), i)
		switch f.Type.Kind() {
		case reflect.String:
			name := fieldPath(reflect.TypeOf(Config{}), path)
			*out = append(*out, configField{
				Path: name,
				Set: func(cfg Config, value string) Config {
					v := reflect.ValueOf(&cfg).Elem()
					fieldByPath(v, path).SetString(value)
					return cfg
				},
			})
		case reflect.Pointer:
			if f.Type.Elem().Kind() != reflect.Struct {
				t.Fatalf("%s.%s is a pointer to %s, which this derivation cannot classify",
					typ.Name(), f.Name, f.Type.Elem().Kind())
			}
			walk(t, f.Type.Elem(), path, out)
		default:
			t.Fatalf("%s.%s is a %s, which this derivation cannot classify: decide what unset "+
				"means for it and teach this test, rather than leaving it out",
				typ.Name(), f.Name, f.Type.Kind())
		}
	}
}

// fieldByPath resolves an index path, allocating nothing: every pointer on the
// path is expected to be non-nil, because the path came from a fully-populated
// configuration.
func fieldByPath(v reflect.Value, path []int) reflect.Value {
	for _, i := range path {
		if v.Kind() == reflect.Pointer {
			v = v.Elem()
		}
		v = v.Field(i)
	}
	return v
}

func fieldPath(root reflect.Type, path []int) string {
	var parts []string
	typ := root
	for _, i := range path {
		if typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		f := typ.Field(i)
		parts = append(parts, f.Name)
		typ = f.Type
	}
	return strings.Join(parts, ".")
}

// TestEveryConfigurationFieldIsRequiredAndHasNoDefault is the ticket, as a
// property.
//
// For every derived field: blanking it must make Validate refuse, and must make
// NewProvider refuse. Both, because a composition root may call either, and a
// configuration that validates and then builds a provider with a substituted
// value is exactly the defect this ticket exists to remove.
func TestEveryConfigurationFieldIsRequiredAndHasNoDefault(t *testing.T) {
	t.Parallel()
	fields := derivedConfigFields(t)
	t.Logf("derived %d configuration fields: %s", len(fields), strings.Join(pathsOf(fields), ", "))

	for _, f := range fields {
		t.Run(f.Path, func(t *testing.T) {
			t.Parallel()
			blanked := f.Set(fullConfig(), "")
			if err := blanked.Validate(); err == nil {
				t.Fatalf("%s may be left unset", f.Path)
			} else if !strings.Contains(err.Error(), f.Path) {
				// The message has to name the field, or an operator cannot act on
				// it. It must not contain the value, which is why the test looks
				// for the name rather than printing the config.
				t.Fatalf("the error for an unset %s does not name it: %v", f.Path, err)
			}
			if _, err := NewProvider(blanked, nil, nil); err == nil {
				t.Fatalf("NewProvider accepted a configuration with %s unset", f.Path)
			}
		})
	}
}

// TestTheRequiredFieldsTestIsNotVacuous is the control in the other direction.
//
// Every case above asserts a refusal, so a Validate that refused everything would
// pass all of them. This asserts the complete configuration is accepted, and that
// each field is accepted at a second, different value -- so a Validate that
// accepted exactly the one fixture would fail too.
func TestTheRequiredFieldsTestIsNotVacuous(t *testing.T) {
	t.Parallel()
	if err := fullConfig().Validate(); err != nil {
		t.Fatalf("the complete configuration was refused: %v", err)
	}
	alternatives := map[string]string{
		"Region":                        "eu-example-2",
		"Dynamic.RoleARN":               "arn:aws:iam::" + testAccount() + ":role/another-example",
		"Dynamic.SessionNamePrefix":     "another",
		"Static.UserPath":               "/another/nested/",
		"Static.UserNamePrefix":         "another",
		"Static.PolicyARN":              "arn:aws:iam::" + testAccount() + ":policy/customer-managed",
		"Static.PermissionsBoundaryARN": "arn:aws:iam::" + testAccount() + ":policy/customer-boundary",
	}
	fields := derivedConfigFields(t)
	if len(alternatives) != len(fields) {
		t.Fatalf("this test knows a second value for %d fields and the derivation found %d; "+
			"a field added to Config needs one here too", len(alternatives), len(fields))
	}
	for _, f := range fields {
		alt, ok := alternatives[f.Path]
		if !ok {
			t.Fatalf("no second value for %s", f.Path)
		}
		if err := f.Set(fullConfig(), alt).Validate(); err != nil {
			t.Fatalf("%s = a different legal value was refused: %v", f.Path, err)
		}
	}
}

func pathsOf(fields []configField) []string {
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		out = append(out, f.Path)
	}
	return out
}

// TestAnUnconfiguredCredentialTypeIsNotOffered covers the pointer fields the
// derivation recurses through rather than checks.
//
// A nil sub-configuration is not a misconfiguration: it says the deployment does
// not offer that credential type. What must not happen is a nil reading as
// "offered with everything unset".
func TestAnUnconfiguredCredentialTypeIsNotOffered(t *testing.T) {
	t.Parallel()
	if _, err := NewProvider(Config{Region: testRegion}, nil, nil); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("a configuration offering neither type was accepted: %v", err)
	}
	// And a zero-valued sub-configuration is a misconfiguration, which is the
	// state a nil must not be confused with.
	if err := (Config{Region: testRegion, Static: &StaticConfig{}}).Validate(); err == nil {
		t.Fatal("a zero-valued StaticConfig validated")
	}
	if err := (Config{Region: testRegion, Dynamic: &DynamicConfig{}}).Validate(); err == nil {
		t.Fatal("a zero-valued DynamicConfig validated")
	}
}

// TestValidateRefusesShapesAWSWouldReject covers the other half of validation:
// a field that is set and is not something AWS accepts.
//
// The role ARN cases are the interesting ones. A provider that accepted any
// string there would send whatever it was given to STS, and an operator's typo in
// a role ARN is a request to assume something else.
func TestValidateRefusesShapesAWSWouldReject(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		cfg  Config
	}{
		// The host is under .invalid rather than .example: the repository's secret
		// scan allowlists the RFC 2606 documentation domains and the reserved
		// .invalid, .test and .localhost TLDs, and not the reserved .example TLD.
		// Renaming the fixture is the fix; loosening a hostname recogniser to admit
		// a false positive is how a recogniser stops catching the real thing.
		{"a region with a dot in it, which is an endpoint substitution", withRegion("us-east-1.attacker.invalid")},
		{"a region with a slash in it", withRegion("us-east-1/x")},
		{"a region in upper case", withRegion("US-EAST-1")},
		{"a role ARN that is a user ARN", withRole("arn:aws:iam::" + testAccount() + ":user/example")},
		{"a role ARN with no account", withRole("arn:aws:iam::aws:role/example")},
		{"a role ARN that is not an ARN", withRole("example-vending-role")},
		{"a policy ARN that is a role ARN", withPolicy("arn:aws:iam::" + testAccount() + ":role/example")},
		{"a policy ARN in another service", withPolicy("arn:aws:s3:::example/policy")},
		{"a boundary that is not a policy", withBoundary("arn:aws:iam::" + testAccount() + ":role/example")},
		{"an IAM path with no leading slash", withUserPath("example/")},
		{"an IAM path with no trailing slash", withUserPath("/example")},
		{"an IAM path that is a bare word", withUserPath("example")},
		{"a user-name prefix with a space", withUserPrefix("example platform")},
		{"a user-name prefix with a slash", withUserPrefix("example/platform")},
		{"a session-name prefix with a colon", withSessionPrefix("example:platform")},
		{"a region with leading whitespace", withRegion(" " + testRegion)},
		{"a user-name prefix long enough to leave no room for a name", withUserPrefix(strings.Repeat("p", maxIAMUserName))},
		{"a session-name prefix long enough to leave no room", withSessionPrefix(strings.Repeat("p", maxRoleSessionName))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := tc.cfg.Validate(); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func withRegion(v string) Config        { c := fullConfig(); c.Region = v; return c }
func withRole(v string) Config          { c := fullConfig(); c.Dynamic.RoleARN = v; return c }
func withSessionPrefix(v string) Config { c := fullConfig(); c.Dynamic.SessionNamePrefix = v; return c }
func withPolicy(v string) Config        { c := fullConfig(); c.Static.PolicyARN = v; return c }
func withBoundary(v string) Config {
	c := fullConfig()
	c.Static.PermissionsBoundaryARN = v
	return c
}
func withUserPath(v string) Config   { c := fullConfig(); c.Static.UserPath = v; return c }
func withUserPrefix(v string) Config { c := fullConfig(); c.Static.UserNamePrefix = v; return c }

// TestValidateAcceptsTheShapesAWSDoes is the control for the table above, and it
// matters more than usual: every case there is a rejection, and a validator that
// rejected every ARN would pass all of them while making the provider unusable.
func TestValidateAcceptsTheShapesAWSDoes(t *testing.T) {
	t.Parallel()
	accepted := []Config{
		withRegion("us-example-1"),
		withRegion("cn-example-1"),
		withRegion("us-gov-example-1"),
		withRole("arn:aws:iam::" + testAccount() + ":role/example"),
		withRole("arn:aws:iam::" + testAccount() + ":role/nested/path/example"),
		withRole("arn:aws-cn:iam::" + testAccount() + ":role/example"),
		withRole("arn:aws-us-gov:iam::" + testAccount() + ":role/example"),
		withPolicy("arn:aws:iam::aws:policy/ExampleManaged"),
		withPolicy("arn:aws:iam::aws:policy/service-role/ExampleManaged"),
		withPolicy("arn:aws:iam::" + testAccount() + ":policy/ExampleCustomerManaged"),
		withBoundary("arn:aws:iam::" + testAccount() + ":policy/ExampleBoundary"),
		withUserPath("/"),
		withUserPath("/example/"),
		withUserPath("/a/b/c/"),
		withUserPrefix("example.platform_v2+x=1,y@z-w"),
		withSessionPrefix("example.platform_v2+x=1,y@z-w"),
	}
	for _, cfg := range accepted {
		if err := cfg.Validate(); err != nil {
			t.Fatalf("refused a configuration AWS accepts: %v", err)
		}
	}
}

// TestAConfigurationErrorNeverEchoesTheValue keeps the invariant the rest of the
// credentials packages hold.
//
// A configuration value is not credential material by intent, and a mistyped
// secret in a configuration field is the most ordinary way one arrives somewhere
// it should not be.
func TestAConfigurationErrorNeverEchoesTheValue(t *testing.T) {
	t.Parallel()
	// The sentinel has to be rejected by every field's grammar, or the test says
	// nothing about the field that accepted it. Spaces do that: no region, no IAM
	// name, no IAM path and no ARN admits one. A hyphenated word does not -- the
	// first version of this test used one and three fields accepted it, which is
	// the instrument being wrong rather than three defects.
	const sentinel = "correct horse battery staple"
	fields := derivedConfigFields(t)
	for _, f := range fields {
		t.Run(f.Path, func(t *testing.T) {
			t.Parallel()
			cfg := f.Set(fullConfig(), sentinel)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("%s accepted %q", f.Path, sentinel)
			}
			if strings.Contains(err.Error(), sentinel) {
				t.Fatalf("the error echoes the rejected value: %v", err)
			}
			if _, perr := NewProvider(cfg, nil, nil); perr == nil {
				t.Fatalf("NewProvider accepted %q in %s", sentinel, f.Path)
			} else if strings.Contains(perr.Error(), sentinel) {
				t.Fatalf("NewProvider's error echoes the rejected value: %v", perr)
			}
		})
	}
}
