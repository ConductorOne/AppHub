// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package secrethandoff_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/conductorone/apphub/compute"
	cp "github.com/conductorone/apphub/internal/controlplane"
	"github.com/conductorone/apphub/internal/secrethandoff"
)

// testAccount is not a twelve-digit number, so no reader or scanner mistakes it
// for a real account; Region does not validate the account segment's shape.
const testAccount = "test-account"

const keyARN = "arn:aws:kms:us-east-1:" + testAccount + ":key/test-key-id"

// fakeKMS models the property the design depends on: a ciphertext decrypts
// only under the exact key and encryption context it was sealed with.
type fakeKMS struct {
	sealed map[string]sealedEntry
	fail   error
}

type sealedEntry struct {
	key       string
	context   map[string]string
	plaintext []byte
}

func newFakeKMS() *fakeKMS { return &fakeKMS{sealed: map[string]sealedEntry{}} }

func (f *fakeKMS) Encrypt(_ context.Context, in *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	if f.fail != nil {
		return nil, f.fail
	}
	blob := fmt.Sprintf("blob-%d", len(f.sealed))
	f.sealed[blob] = sealedEntry{key: aws.ToString(in.KeyId), context: maps.Clone(in.EncryptionContext), plaintext: bytes.Clone(in.Plaintext)}
	return &kms.EncryptOutput{CiphertextBlob: []byte(blob)}, nil
}

func (f *fakeKMS) Decrypt(_ context.Context, in *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	if f.fail != nil {
		return nil, f.fail
	}
	e, ok := f.sealed[string(in.CiphertextBlob)]
	if !ok || e.key != aws.ToString(in.KeyId) || !maps.Equal(e.context, in.EncryptionContext) {
		return nil, errors.New("InvalidCiphertextException: arn:aws:kms:... leaked detail")
	}
	return &kms.DecryptOutput{Plaintext: bytes.Clone(e.plaintext)}, nil
}

func pair(t *testing.T) (*secrethandoff.Sealer, *secrethandoff.Opener, *fakeKMS) {
	t.Helper()
	f := newFakeKMS()
	sealer, err := secrethandoff.NewSealerWithAPI(f, keyARN)
	if err != nil {
		t.Fatal(err)
	}
	opener, err := secrethandoff.NewOpenerWithAPI(f, keyARN)
	if err != nil {
		t.Fatal(err)
	}
	return sealer, opener, f
}

func TestASealedValueOpensOnlyForItsOwnSubject(t *testing.T) {
	sealer, opener, _ := pair(t)
	subject := cp.SecretSubject{ApplicationID: "app-1", DeploymentID: "dep-1", Name: "STRIPE_KEY"}
	ciphertext, err := sealer.Seal(t.Context(), subject, []byte("sk_live_1"))
	if err != nil {
		t.Fatal(err)
	}
	value, err := opener.Open(t.Context(), subject, ciphertext)
	if err != nil || compute.RevealSecret(value) != "sk_live_1" {
		t.Fatalf("round trip failed: %v", err)
	}
	for name, other := range map[string]cp.SecretSubject{
		"another deployment":  {ApplicationID: "app-1", DeploymentID: "dep-2", Name: "STRIPE_KEY"},
		"another application": {ApplicationID: "app-2", DeploymentID: "dep-1", Name: "STRIPE_KEY"},
		"another secret":      {ApplicationID: "app-1", DeploymentID: "dep-1", Name: "OTHER"},
	} {
		if _, err := opener.Open(t.Context(), other, ciphertext); !errors.Is(err, secrethandoff.ErrUnavailable) {
			t.Errorf("%s: got %v; want the ciphertext refused", name, err)
		}
	}
}

func TestKMSErrorTextNeverReachesTheCaller(t *testing.T) {
	sealer, opener, f := pair(t)
	subject := cp.SecretSubject{ApplicationID: "a", DeploymentID: "d", Name: "N"}
	_, err := opener.Open(t.Context(), subject, []byte("unknown"))
	if err == nil || strings.Contains(err.Error(), "arn:aws") || strings.Contains(err.Error(), "InvalidCiphertext") {
		t.Fatalf("got %v; want a generic error", err)
	}
	f.fail = errors.New("AccessDeniedException: role arn:aws:iam::123:role/x")
	if _, err := sealer.Seal(t.Context(), subject, []byte("v")); !errors.Is(err, secrethandoff.ErrUnavailable) || strings.Contains(err.Error(), "arn:aws") {
		t.Fatalf("got %v; want a generic error", err)
	}
}

func TestAnIncompleteSubjectIsRefused(t *testing.T) {
	sealer, _, _ := pair(t)
	if _, err := sealer.Seal(t.Context(), cp.SecretSubject{ApplicationID: "a", Name: "N"}, []byte("v")); !errors.Is(err, secrethandoff.ErrConfiguration) {
		t.Fatalf("got %v; want a refusal for a missing deployment", err)
	}
}

func TestOnlyAKMSKeyOrAliasARNIsAccepted(t *testing.T) {
	for arn, ok := range map[string]bool{
		keyARN: true,
		"arn:aws:kms:eu-west-1:" + testAccount + ":alias/apphub-secret-handoff": true,
		"test-key-id":                            false,
		"alias/apphub":                           false,
		"arn:aws:s3:::bucket":                    false,
		"arn:aws:kms::" + testAccount + ":key/x": false,
		"":                                       false,
	} {
		if _, err := secrethandoff.Region(arn); (err == nil) != ok {
			t.Errorf("Region(%q) = %v; want ok=%t", arn, err, ok)
		}
	}
}
