// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/conductorone/apphub/compute"
)

// The label and annotation vocabulary this provider owns.
//
// managedBy is the ownership marker [compute.ErrNotOwned] requires every
// provider to have. It is a label rather than an annotation so that teardown by
// scope can select on it.
const (
	labelManagedBy = "app.kubernetes.io/managed-by"
	labelName      = "app.kubernetes.io/name"
	labelComponent = "app.kubernetes.io/component"
	labelScope     = "apphub.dev/scope"
	labelIdentity  = "apphub.dev/workload-identity"
	managedByValue = "apphub"

	// annotationLabels carries the caller's [compute.ServiceSpec.Labels] and
	// friends.
	//
	// They cannot be Kubernetes labels. A Kubernetes label value must be at
	// most 63 characters of alphanumerics, dashes, underscores and dots, and a
	// key must be a qualified name; the interface promises neither, so a
	// provider that copied them across would reject specs the interface says
	// are valid. Nor can they be one annotation each, because an annotation key
	// has the same grammar as a label key. So they are escaped into a single
	// annotation, and the cost — they are no longer selectable, which is half
	// of what "ownership tagging" means on this substrate — is recorded as a
	// finding in docs/design/k8s-contract-probe.md.
	annotationLabels = "apphub.dev/labels"

	// annotationSpec carries the effective spec the provider converged to, so
	// that a Describe can return it (F6). Recording the desired state on the
	// object is the substrate's own idiom — it is what
	// kubectl.kubernetes.io/last-applied-configuration is — and it beats
	// reconstructing a spec field by field from a rendered object, which loses
	// exactly the fields a caller most wants to check for removal.
	//
	// It never carries material: a [compute.SecretBinding] is a reference, and a
	// spec with a [compute.SecretValue] in it is zeroed before it is written.
	annotationSpec = "apphub.dev/spec"

	// annotationCapacityUnits records the abstract [compute.CapacityRange] the
	// caller asked for, because the substrate keeps only the translation.
	annotationCapacityUnits = "apphub.dev/capacity-units"

	// annotationEndpointHostname records the hostname a function endpoint
	// answers on.
	annotationEndpointHostname = "apphub.dev/endpoint-hostname"
)

// Kinds this provider writes. The two custom resources are named rather than
// typed because which operator is installed is configuration.
const (
	kindPostgresCluster = "Cluster"
	kindGateway         = "Gateway"
	kindHTTPRoute       = "HTTPRoute"

	postgresPhaseCreating = "Setting up primary"
	postgresPhaseHealthy  = "Cluster in healthy state"

	protocolHTTP  = "HTTP"
	protocolHTTPS = "HTTPS"
)

// schemaGVK is a local alias, so the many places that pass one around do not
// each have to import the schema package.
type schemaGVK = schema.GroupVersionKind

// GroupVersionKinds for the built-in objects.
var (
	gvkServiceAccount = schema.GroupVersionKind{Version: "v1", Kind: "ServiceAccount"}
	gvkSecret         = schema.GroupVersionKind{Version: "v1", Kind: "Secret"}
	gvkConfigMap      = schema.GroupVersionKind{Version: "v1", Kind: "ConfigMap"}
	gvkService        = schema.GroupVersionKind{Version: "v1", Kind: "Service"}
	gvkDeployment     = schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"}
	gvkCronJob        = schema.GroupVersionKind{Group: "batch", Version: "v1", Kind: "CronJob"}
	gvkNetworkPolicy  = schema.GroupVersionKind{Group: "networking.k8s.io", Version: "v1", Kind: "NetworkPolicy"}
	gvkIngress        = schema.GroupVersionKind{Group: "networking.k8s.io", Version: "v1", Kind: "Ingress"}
	gvkRoleBinding    = schema.GroupVersionKind{Group: "rbac.authorization.k8s.io", Version: "v1", Kind: "RoleBinding"}
	gvkGateway        = schema.GroupVersionKind{Group: "gateway.networking.k8s.io", Version: "v1", Kind: kindGateway}
	gvkHTTPRoute      = schema.GroupVersionKind{Group: "gateway.networking.k8s.io", Version: "v1", Kind: kindHTTPRoute}
)

// The object-name prefixes that keep two ports from colliding on one logical
// name. A service and a function may both be called "api"; on AWS they are
// different services entirely, and here they would be two Deployments in one
// namespace.
const (
	prefixService  = "svc-"
	prefixJob      = "job-"
	prefixFunction = "fn-"
	prefixEndpoint = "ep-"
	prefixDatabase = "db-"
)

// dns1123 is the name grammar Kubernetes applies to almost every object.
var dns1123 = regexp.MustCompile(`[^a-z0-9-]+`)

// maxObjectName is the DNS-1123 subdomain limit. Names that feed a label value
// or a Service name are shorter still; the provider uses the tighter bound
// everywhere so one logical name cannot be legal for a Deployment and illegal
// for the Service in front of it.
const maxObjectName = 63

// sanitize turns a logical name into a legal Kubernetes object name,
// deterministically.
//
// Determinism is a contract, not a convenience: teardown has to be able to
// reconstruct a reference from a logical name whose provisioned identifier may
// never have been persisted. A truncation therefore carries a digest of the
// full input rather than just dropping the tail, so two long names that share a
// prefix do not become the same object.
func sanitize(prefix, name string) string {
	clean := dns1123.ReplaceAllString(strings.ToLower(name), "-")
	clean = strings.Trim(clean, "-")
	if clean == "" {
		clean = "x"
	}
	full := prefix + clean
	if len(full) <= maxObjectName {
		return full
	}
	sum := sha256.Sum256([]byte(name))
	suffix := "-" + hex.EncodeToString(sum[:])[:8]
	keep := maxObjectName - len(prefix) - len(suffix)
	return prefix + strings.Trim(clean[:keep], "-") + suffix
}

// hash8 is a short, stable digest used where a name has to encode something a
// Kubernetes name cannot hold literally.
func hash8(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:8]
}

// validateName rejects a logical name that cannot become a legal object name at
// all, so the caller learns at the spec rather than from the API server.
func validateName(name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("%w: the resource name is empty", compute.ErrInvalidSpec)
	}
	return nil
}

// validateLabels rejects caller metadata this provider cannot carry.
//
// Only the key grammar is constrained, and only enough to keep the escaped
// annotation unambiguous. Everything else the interface permits is accepted,
// which is why the labels end up in one annotation rather than as real labels.
func validateLabels(labels map[string]string) error {
	for k := range labels {
		if k == "" || strings.ContainsAny(k, "= \t\n") {
			return fmt.Errorf("%w: label key %q contains a character this provider cannot encode; "+
				"Kubernetes label and annotation keys are qualified names, so apphub escapes the "+
				"caller's labels into one annotation and needs the key to be free of '=' and "+
				"whitespace", compute.ErrInvalidSpec, k)
		}
	}
	return nil
}

// encodeLabels renders the caller's labels for annotationLabels.
func encodeLabels(labels map[string]string) string { return sortedPairs(labels) }

// ownershipLabels are the labels every object this provider creates carries.
func ownershipLabels(name, component string, extra map[string]string) map[string]string {
	out := map[string]string{
		labelManagedBy: managedByValue,
		labelName:      name,
	}
	if component != "" {
		out[labelComponent] = component
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// annotationsFor builds the annotation map an object carries.
// encodeSpec renders an effective spec for [annotationSpec]. A spec that cannot
// be rendered is a programming error rather than a caller error, so it degrades
// to an empty annotation and a Describe that reports no spec, which the
// conformance suite catches.
func encodeSpec(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// reencodeSpec updates the effective spec an object carries, in place.
//
// It exists so that a method mutating a stored object has one obvious call to
// make. Every Ensure path writes the annotation as part of rendering the whole
// object; a method that changes one field of an object it read back has to keep
// the annotation in step by hand, and the one that did not was
// [containerRuntime.ScaleService] -- where the omission made
// ServiceStatus.Spec.Replicas disagree with ServiceStatus.DesiredReplicas for the
// same resource at the same moment.
//
// # Two questions, because the round-trip only answers one of them
//
// A gate here has to establish two separate things, and round seven found that
// one check was being read as answering both:
//
//  1. **Provenance** -- could a successful Ensure have written this? and
//  2. **Canonicality** -- is it in the exact form this build writes?
//
// The byte round-trip answers (2). It does NOT answer (1), and the counter-example
// is not exotic: `json.Marshal(compute.ServiceSpec{})` **is** a byte fixed point,
// so the canonical zero spec sailed through the round-trip guard -- and it is a
// value no successful Ensure can ever produce, because Ensure refuses a spec with
// no image and no resources. So the fabrication path four rounds had been spent
// closing was still reachable, through a *canonical* annotation rather than a
// malformed one. **The guard was testing self-consistency where it was placed to
// test provenance.** Self-consistency is a property a forgery has too.
//
// Both are checked now, in that order, because the order decides which diagnosis
// an operator gets. A spec from a different build passes (1) and fails (2), so it
// is reported as version skew. A zero or partial spec fails (1) first, so it is
// reported as something this provider never wrote -- which is what it is, and
// calling it version skew would send the operator to the wrong place.
//
// The provenance check is supplied by the caller and **reuses the validation the
// Ensure path itself runs** rather than restating it. That is deliberate: a second
// list of invariants beside Ensure's own is a list that drifts, and the question
// being asked is literally "would Ensure have accepted this", so the honest
// implementation is to ask Ensure's validator.
//
// # It refuses a CLASS of annotation rather than a list of bad inputs
//
// Three rounds of review found three inputs, one at a time: absent, then
// unparseable, then valid-but-incomplete. `{}` is valid JSON, unmarshals without
// error into the zero spec, and so walked through both earlier checks -- and the
// mutation was then applied to a fabricated spec, which is worse than a garbled
// one because garbled state shows that something is wrong.
//
// Enumerating a fourth input would have been the same mistake a third time, so the
// condition is not a list. **An effective spec this provider wrote is a fixed
// point of encode-then-decode**, byte for byte: [encodeSpec] is
// [encoding/json.Marshal], the spec types declare no `omitempty`, and struct
// fields marshal in declaration order, so re-encoding what we decoded reproduces
// exactly what we read. Anything that is not that fixed point is something this
// provider could not have written, whatever the reason -- absent, malformed,
// truncated, partial, hand-edited, or a form nobody has thought of yet -- and it
// is refused without needing to be recognised.
//
// The error still names which case it saw where it can tell, because absent,
// unparseable and incomplete send an operator to different places. But the
// *decision* is one predicate.
//
// # What this deliberately refuses that it might have accepted
//
// An annotation written by a build whose spec type had a different field set is
// not a fixed point either, so an upgrade that adds a field makes ScaleService
// refuse until the object is re-rendered by an Ensure. That is the fail-closed
// side of the trade and it is the right one here: the alternative is deciding, at
// a mutation site, which missing fields are safe to invent.
//
// **The refusal says so, in those words, and that is load-bearing.** Fail-closed
// becomes fail-confusing if an operator who hits this after an upgrade cannot tell
// it from corruption, so the message names version skew as the usual cause, names
// the remedy (run an Ensure, which re-renders the annotation), and says what it
// means if the remedy does not work.
func reencodeSpec[T any](annotations map[string]string, mutate func(T) T, couldHaveWritten func(T) error) error {
	raw, ok := annotations[annotationSpec]
	if annotations == nil || !ok || raw == "" {
		return fmt.Errorf("%w: this object carries no effective spec to update, so a mutation "+
			"would leave its read-back disagreeing with its fields", compute.ErrFailed)
	}
	var current T
	if err := json.Unmarshal([]byte(raw), &current); err != nil {
		return fmt.Errorf("%w: this object's effective spec is not valid JSON, so a mutation "+
			"would replace it with a fabricated one rather than an updated one: %w",
			compute.ErrFailed, err)
	}
	// Question 1, provenance. Asked BEFORE canonicality so that a spec this
	// provider never wrote is not misreported as version skew.
	if err := couldHaveWritten(current); err != nil {
		return fmt.Errorf("%w: this object's effective spec parses and is in this build's exact "+
			"format, but it is not a spec a successful Ensure could have written -- the same "+
			"validation the Ensure path applies rejects it: %w. The canonical zero spec is the "+
			"case that motivated this check: it IS a byte fixed point of encode-then-decode, so "+
			"a round-trip guard admits it, and mutating it would fabricate an effective spec "+
			"rather than update one",
			compute.ErrFailed, err)
	}
	// Question 2, canonicality: what we decoded has to re-encode to what we read.
	// An annotation this build wrote does. This is the version-skew check, and it
	// is NOT the provenance check -- see the two-questions section above for the
	// canonical-zero counter-example that distinguishes them.
	if round := encodeSpec(current); round != raw {
		return fmt.Errorf("%w: this object's effective-spec annotation was not written by this "+
			"build of the provider -- it parses, but re-rendering what it parses to yields %d "+
			"bytes where %d are stored, so the spec type has gained, lost, or reordered a field. "+
			"The usual cause is VERSION SKEW: the object was rendered by a different provider "+
			"version. Run an Ensure against this resource to re-render the annotation, after "+
			"which this operation will work. If an Ensure does not fix it, the annotation was "+
			"written by something that is not this provider. Refusing here rather than mutating "+
			"is deliberate: the alternative is deciding which absent fields are safe to invent",
			compute.ErrFailed, len(round), len(raw))
	}
	annotations[annotationSpec] = encodeSpec(mutate(current))
	return nil
}

// decodeSpec reads back what encodeSpec wrote.
//
// A missing (or empty) annotation yields the zero spec and a nil error:
// absence is a legitimate state -- an object this provider has not yet
// rendered, or one this build has not yet reconciled -- not a defect. A
// *present* annotation that fails to unmarshal into T is a defect: something
// wrote a value into a field this package treats as its own private
// read-back, and that is not the same situation as the field never having
// been set.
//
// Before this returned an error, both cases produced the identical zero
// spec, so a caller had no way to tell "nobody has written this yet" from
// "somebody wrote garbage here" -- see TestDecodeSpecDistinguishesAbsentFromMalformed
// and the callers below, each of which now decides for itself whether a
// malformed annotation on its own kind of object is worth surfacing as
// [compute.ErrFailed] or worth tolerating like an absent one.
func decodeSpec[T any](annotations map[string]string) (T, error) {
	var out T
	raw, ok := annotations[annotationSpec]
	if !ok || raw == "" {
		return out, nil
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return out, fmt.Errorf("%w: this object's effective-spec annotation is not valid JSON: %w",
			compute.ErrFailed, err)
	}
	return out, nil
}

// copyLabels returns a map that shares no storage with the one it was given.
//
// A read-back that hands out the provider's own map lets a caller rewrite what
// the provider believes it deployed by editing a label it was shown. The
// conformance suite checks for it on every port; it found this provider doing it
// on two.
func copyLabels(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func annotationsFor(labels map[string]string, extra map[string]string) map[string]string {
	out := map[string]string{annotationLabels: encodeLabels(labels)}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// --- references -------------------------------------------------------------

// refID composes the opaque part of a [compute.Ref].
//
// The shape is "<resource>/<namespace>/<name>" so that one provider can address
// several kinds of object without the parser ever leaving this file. Callers
// must not read it; [compute.Ref] says so, and the conformance suite checks
// that the round trip through [compute.Ref.String] survives the colons.
func refID(resource, namespace, name string) string {
	return resource + "/" + namespace + "/" + name
}

// parseRefID is the inverse. It returns [compute.ErrNotFound] shaped errors
// nowhere: a malformed ID is a caller bug.
func parseRefID(id string) (resource, namespace, name string, ok bool) {
	parts := strings.SplitN(id, "/", 3)
	if len(parts) != 3 || parts[0] == "" || parts[2] == "" {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

// resourceOf names the ID prefix each [compute.Kind] uses.
var resourceOf = map[compute.Kind]string{
	compute.KindWorkloadIdentity: "serviceaccounts",
	compute.KindImageRepository:  "repositories",
	compute.KindSecret:           "secrets",
	compute.KindBucket:           "buckets",
	compute.KindService:          "deployments",
	compute.KindScheduledJob:     "cronjobs",
	compute.KindFunction:         "functions",
	compute.KindFunctionEndpoint: "gateways",
	compute.KindRelational:       "postgresclusters",
	compute.KindKeyValueTable:    "keyvaluetables",
}

// sortedKeys is a small helper used where output has to be stable.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
