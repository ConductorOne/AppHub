// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"errors"
	"fmt"
	"sort"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// ErrUnmappedKind is returned when nothing maps a kind onto the REST resource
// that addresses it.
//
// It is a first-class error rather than a fallback because the fallback is the
// bug. See [StaticResolver].
var ErrUnmappedKind = errors.New("k8s: no API resource is mapped for this kind")

// APIResource is what a client needs in order to address a kind over REST: the
// plural resource name in the URL path, and whether that path has a namespace
// segment in it.
type APIResource struct {
	// Resource is the plural, lowercase resource name — "deployments".
	Resource string
	// Namespaced reports whether the resource lives in a namespace. A
	// cluster-scoped resource addressed as namespaced 404s, and a namespaced one
	// addressed as cluster-scoped reads across every namespace.
	Namespaced bool
}

// ResourceResolver maps a [schema.GroupVersionKind] onto the resource that
// addresses it.
//
// A client-go dynamic client is addressed by GroupVersionResource, while every
// other layer of this provider — and the [Cluster] seam itself — speaks
// GroupVersionKind, because a kind is what an object *is* and a resource is an
// implementation detail of the API server's routing. Something has to bridge
// them, and how it does so is a correctness question rather than a convenience:
// see [StaticResolver].
type ResourceResolver interface {
	// ResourceFor returns the resource addressing gvk and whether it is
	// namespaced, or an error wrapping [ErrUnmappedKind].
	ResourceFor(gvk schema.GroupVersionKind) (schema.GroupVersionResource, bool, error)
}

// StaticResolver resolves from an explicit table and refuses anything absent
// from it.
//
// # Why not just pluralise the kind
//
// apimachinery ships [meta.UnsafeGuessKindToResource], and it is tempting: one
// call, no table, no maintenance. It is also wrong for a kind this provider
// writes. Its own name says so, and
// [TestGuessingTheResourceNameIsWrongForAKindThisProviderWrites] pins the
// specific failure — it turns Gateway into "gatewaies", because it applies an
// English "-y" → "-ies" rule to a word ending in "-ay".
//
// The failure mode matters more than the instance. A wrong resource name is not
// a compile error and not a validation error: it is a 404 from the API server at
// run time, indistinguishable from "the object does not exist". A provider built
// on the guess would report a Gateway as absent, create a new one on every
// reconcile, and never converge — and every one of its unit tests against a fake
// client would pass, because the fake is addressed by the same wrong resource
// the code asks for. **A fake cannot catch a mapping error, because it agrees
// with whatever the code says.**
//
// So this resolver holds an explicit table and returns [ErrUnmappedKind] for
// anything else, which turns the whole class of mistake from a silent 404 into a
// refusal that names the kind. It is a construction that cannot express the
// violation rather than a check that might notice one.
//
// # What the table has to contain
//
// Everything this provider writes. Two things keep that honest:
// [BuiltinResources] covers the Kubernetes and Gateway API kinds, whose plurals
// are fixed by their own published API surfaces; and the operator supplies the
// custom resources whose names are theirs to choose — the Postgres operator's
// cluster resource is configuration in this provider precisely because
// CloudNativePG, Zalando, and Crunchy disagree about it. A caller that forgets
// one gets [ErrUnmappedKind] on first use, and
// TestEveryKindTheProviderWritesIsResolvable drives the whole conformance
// surface and fails if any kind the provider actually touched is missing from
// the table.
type StaticResolver struct {
	resources map[schema.GroupVersionKind]APIResource
}

var _ ResourceResolver = (*StaticResolver)(nil)

// NewStaticResolver returns a resolver over [BuiltinResources] plus extra.
//
// An entry in extra overrides a built-in of the same kind, which is what an
// operator needs when their cluster serves a kind at a non-standard resource
// name. A malformed entry — empty resource, or a kind with no Kind — is an error
// rather than an entry that will 404 later.
func NewStaticResolver(extra map[schema.GroupVersionKind]APIResource) (*StaticResolver, error) {
	resources := BuiltinResources()
	for gvk, res := range extra {
		if gvk.Kind == "" {
			return nil, fmt.Errorf("k8s: a resource mapping was supplied for a GroupVersionKind "+
				"with no Kind (%s)", gvk.GroupVersion())
		}
		if gvk.Version == "" {
			return nil, fmt.Errorf("k8s: the resource mapping for kind %q names no API version",
				gvk.Kind)
		}
		if res.Resource == "" {
			return nil, fmt.Errorf("k8s: the resource mapping for %s names no resource; a "+
				"client cannot build a URL path without one", gvk)
		}
		resources[gvk] = res
	}
	if len(resources) == 0 {
		// BuiltinResources is a literal, so this is unreachable today. It is
		// asserted anyway: a resolver over an empty table resolves nothing, and
		// every test written over it would pass.
		return nil, errors.New("k8s: the resource table is empty, so no kind could be addressed")
	}
	return &StaticResolver{resources: resources}, nil
}

// ResourceFor implements [ResourceResolver].
func (r *StaticResolver) ResourceFor(gvk schema.GroupVersionKind) (schema.GroupVersionResource, bool, error) {
	res, ok := r.resources[gvk]
	if !ok {
		return schema.GroupVersionResource{}, false, fmt.Errorf(
			"%w: %s; the mapped kinds are %v. A custom resource has to be supplied by the "+
				"operator, because its resource name belongs to whoever installed the CRD",
			ErrUnmappedKind, gvk, r.kinds())
	}
	return gvk.GroupVersion().WithResource(res.Resource), res.Namespaced, nil
}

// Kinds returns the kinds this resolver can address, sorted, so a caller can
// report what an operator still has to configure.
func (r *StaticResolver) Kinds() []schema.GroupVersionKind {
	out := make([]schema.GroupVersionKind, 0, len(r.resources))
	for gvk := range r.resources {
		out = append(out, gvk)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

func (r *StaticResolver) kinds() []string {
	all := r.Kinds()
	out := make([]string, 0, len(all))
	for _, gvk := range all {
		out = append(out, gvk.String())
	}
	return out
}

// BuiltinResources is the resource name and scope of every kind this provider
// writes whose name is fixed by a published API surface: the Kubernetes core,
// apps, batch, networking and RBAC groups, and the Gateway API.
//
// Each entry is a fact about somebody else's API, so each is written out rather
// than computed. The Postgres operator's cluster resource is deliberately absent:
// its API version and kind are already [PostgresOperatorConfig] fields because
// the three operators disagree, so its resource name is the operator's to supply
// too.
//
// The returned map is freshly allocated, so a caller may modify it.
func BuiltinResources() map[schema.GroupVersionKind]APIResource {
	return map[schema.GroupVersionKind]APIResource{
		gvkServiceAccount: {Resource: "serviceaccounts", Namespaced: true},
		gvkSecret:         {Resource: "secrets", Namespaced: true},
		gvkConfigMap:      {Resource: "configmaps", Namespaced: true},
		gvkService:        {Resource: "services", Namespaced: true},
		gvkDeployment:     {Resource: "deployments", Namespaced: true},
		gvkCronJob:        {Resource: "cronjobs", Namespaced: true},
		gvkNetworkPolicy:  {Resource: "networkpolicies", Namespaced: true},
		gvkIngress:        {Resource: "ingresses", Namespaced: true},
		gvkRoleBinding:    {Resource: "rolebindings", Namespaced: true},
		// The Gateway API's own specification fixes these two, so they belong
		// here rather than in operator configuration even though they arrive as
		// CRDs. "gateways" is also the exact spelling apimachinery's guess gets
		// wrong; see StaticResolver.
		gvkGateway:   {Resource: "gateways", Namespaced: true},
		gvkHTTPRoute: {Resource: "httproutes", Namespaced: true},
	}
}

// PostgresResource is the resource mapping for a configured Postgres operator's
// cluster resource, for a caller assembling a [StaticResolver].
//
// The resource name cannot be derived from [PostgresOperatorConfig]: it is the
// plural the CRD author chose, and this provider is written not to assume which
// operator is installed. Supplying it as an explicit argument keeps that
// assumption out of the code and in the caller's configuration, where an
// operator can fix it without a release.
func PostgresResource(cfg *PostgresOperatorConfig, resource string) (map[schema.GroupVersionKind]APIResource, error) {
	if cfg == nil {
		return nil, errors.New("k8s: no Postgres operator is configured, so it needs no resource mapping")
	}
	if resource == "" {
		return nil, fmt.Errorf("k8s: the resource name for %s/%s must be supplied; it is the "+
			"plural the operator's CRD declares and this provider does not guess it",
			cfg.APIVersion, cfg.Kind)
	}
	group, version, err := splitAPIVersion(cfg.APIVersion)
	if err != nil {
		return nil, err
	}
	gvk := schema.GroupVersionKind{Group: group, Version: version, Kind: cfg.Kind}
	if gvk.Kind == "" {
		return nil, errors.New("k8s: the Postgres operator configuration names no Kind")
	}
	return map[schema.GroupVersionKind]APIResource{gvk: {Resource: resource, Namespaced: true}}, nil
}

// splitAPIVersion parses "group/version" or "version", refusing anything else.
//
// parseAPIVersion in names.go does the same job for the render path and ignores
// malformed input, which is right there and wrong here: a bad API version in a
// resolver produces a request to a path nobody serves.
func splitAPIVersion(apiVersion string) (group, version string, err error) {
	gv, err := schema.ParseGroupVersion(apiVersion)
	if err != nil {
		return "", "", fmt.Errorf("k8s: %q is not a valid apiVersion: %w", apiVersion, err)
	}
	if gv.Version == "" {
		return "", "", fmt.Errorf("k8s: %q names no API version", apiVersion)
	}
	return gv.Group, gv.Version, nil
}

// RESTMapperResolver resolves through a [meta.RESTMapper], which is what a
// production caller with API-server access should prefer: a discovery-backed
// mapper reads the resource names and scopes out of the cluster that is going to
// serve the requests, so it cannot disagree with it.
//
// It is not the default because building one requires a round trip to the API
// server, and this package must be constructible — and testable — without one.
type RESTMapperResolver struct{ mapper meta.RESTMapper }

var _ ResourceResolver = (*RESTMapperResolver)(nil)

// NewRESTMapperResolver wraps mapper.
func NewRESTMapperResolver(mapper meta.RESTMapper) (*RESTMapperResolver, error) {
	if mapper == nil {
		return nil, errors.New("k8s: NewRESTMapperResolver needs a RESTMapper")
	}
	return &RESTMapperResolver{mapper: mapper}, nil
}

// ResourceFor implements [ResourceResolver].
func (r *RESTMapperResolver) ResourceFor(gvk schema.GroupVersionKind) (schema.GroupVersionResource, bool, error) {
	mapping, err := r.mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		// Wrapped as ErrUnmappedKind so a caller handles a kind the cluster does
		// not serve the same way whichever resolver is installed. A CRD that is
		// not installed reaches here, and "this cluster does not serve that
		// kind" is exactly what the operator needs to be told.
		return schema.GroupVersionResource{}, false, fmt.Errorf("%w: %s: %w", ErrUnmappedKind, gvk, err)
	}
	return mapping.Resource, mapping.Scope.Name() == meta.RESTScopeNameNamespace, nil
}
