// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package workload

import "github.com/conductorone/apphub/credentials"

// This file is the canonical declaration of the workload-identity attestation
// vocabulary, per /shared/apphub/contracts/workload-identity.md. The type names,
// field names and order, and the Method constant names and values are fixed by
// that contract: compute imports them from here and declares none of its own, so
// a divergence in any detail is not a style difference but two systems disagreeing
// about what a workload proved.

// Method identifies an attestation scheme.
//
// The values are defined here and only here. No string literal naming a scheme
// may appear anywhere else in this package or in compute: a registry keyed by one
// spelling will silently fail to select a provider registered under another,
// which is exactly what happened when two packages independently coined two
// different spellings for the same AWS scheme.
type Method string

const (
	// MethodAWSSTSCallerIdentity is a presigned AWS STS GetCallerIdentity request,
	// replayed by the verifier. The long name is deliberate: it says what is
	// actually proven.
	MethodAWSSTSCallerIdentity Method = "aws-sts-caller-identity"

	// MethodK8sServiceAccount is a projected Kubernetes service-account token.
	MethodK8sServiceAccount Method = "k8s-service-account"
)

// ExpectedAttestation is the stored policy for one workload's identity: what a
// valid workload must prove.
//
// It is configuration, not evidence. It carries no secret material, so it is safe
// to persist and safe to log — and keeping it structurally incapable of holding
// material is what stops the stored expectation from becoming a second copy of
// the thing being proven.
//
// Produced by compute when a workload is provisioned, persisted by the deploy
// layer, and handed to the verifier at check time.
type ExpectedAttestation struct {
	// Method is the attestation scheme this workload uses.
	Method Method
	// Subject is the identity the proof must resolve to, exactly.
	Subject string
	// Issuer is the required issuer, for schemes that have one.
	Issuer string
	// Audience is the required audience, for schemes that have one.
	Audience string
}

// AttestationProof is the runtime evidence a workload submits to claim its
// identity.
//
// It carries secret material — a SigV4 Authorization header is a bearer
// credential for as long as its signature is valid, and a projected token is a
// token — so it must never be persisted and never logged.
//
// Proof is an opaque map because what constitutes evidence is scheme-specific,
// and keeping it opaque is what lets a second scheme arrive without changing this
// type, the handler that receives it, or the compute layer that delivered its
// inputs. Only a Verifier for that Method knows what the keys mean.
type AttestationProof struct {
	// Method is the scheme the submitter claims to be using.
	Method Method
	// Proof is the scheme-specific evidence, including the deploy secret the
	// platform injected at provisioning time.
	Proof map[string]credentials.Secret
}
