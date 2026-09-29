// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

// observe advances whatever controller would be reconciling this object.
//
// # Why a read is the clock
//
// A cluster with no kubelet has nothing to make a Deployment's pods ready, and
// a probe that used wall-clock time would trade a fast hermetic suite for
// sleeps. So convergence advances on observation: the first read of a freshly
// applied object reports it progressing, the second reports it converged. That
// is enough to exercise every invariant the interface states about phases,
// because none of them is about duration — [compute.Status] is careful to say
// the caller chooses the deadline, not the provider.
//
// [MemoryCluster.stall] switches this off for one object, which is what gives
// the conformance suite something for a Wait to time out on.
func (c *MemoryCluster) observe(e *entry) {
	if e.stalled {
		return
	}
	e.observations++
	switch obj := e.object.(type) {
	case *appsv1.Deployment:
		reconcileDeployment(obj, e)
	case *unstructured.Unstructured:
		reconcileUnstructured(obj, e)
	}
}

// converged reports whether enough observations have accumulated for the
// object to be considered reconciled. Two, so that a caller always sees at
// least one intermediate state and OnUpdate has something to report.
func (e *entry) converged() bool { return e.observations >= 2 }

// reconcileDeployment writes the status a Deployment controller and a kubelet
// would between them produce.
func reconcileDeployment(d *appsv1.Deployment, e *entry) {
	desired := int32(1)
	if d.Spec.Replicas != nil {
		desired = *d.Spec.Replicas
	}
	d.Status.ObservedGeneration = e.generation
	d.Status.Replicas = desired
	if !e.converged() {
		d.Status.ReadyReplicas = 0
		d.Status.AvailableReplicas = 0
		d.Status.Conditions = []appsv1.DeploymentCondition{{
			Type:   appsv1.DeploymentProgressing,
			Status: corev1.ConditionTrue,
			Reason: "ReplicaSetUpdated",
		}}
		return
	}
	d.Status.ReadyReplicas = desired
	d.Status.AvailableReplicas = desired
	d.Status.Conditions = []appsv1.DeploymentCondition{{
		Type:   appsv1.DeploymentAvailable,
		Status: corev1.ConditionTrue,
		Reason: "MinimumReplicasAvailable",
	}}
}

// reconcileUnstructured stands in for the operators behind the two custom
// resources this provider writes: the Postgres operator and the Gateway API
// controller. Both are ordinary controllers that watch a spec and write a
// status, which is the whole reason the provider can be written against them
// without knowing which implementation is installed.
func reconcileUnstructured(u *unstructured.Unstructured, e *entry) {
	status := map[string]any{"observedGeneration": e.generation}
	switch u.GetKind() {
	case kindPostgresCluster:
		instances, _, _ := unstructured.NestedInt64(u.Object, "spec", "instances")
		if !e.converged() {
			status["phase"] = postgresPhaseCreating
			status["readyInstances"] = int64(0)
		} else {
			status["phase"] = postgresPhaseHealthy
			status["readyInstances"] = instances
			status["writeService"] = u.GetName() + "-rw." + u.GetNamespace() + ".svc.cluster.local"
		}
	case kindGateway:
		if !e.converged() {
			status["conditions"] = []any{condition("Programmed", string(metav1.ConditionFalse), "Pending")}
		} else {
			status["conditions"] = []any{condition("Programmed", string(metav1.ConditionTrue), "Programmed")}
			if host := u.GetAnnotations()[annotationEndpointHostname]; host != "" {
				status["addresses"] = []any{map[string]any{"type": "Hostname", "value": host}}
			}
		}
	default:
		return
	}
	u.Object["status"] = status
}

func condition(t, s, reason string) map[string]any {
	return map[string]any{"type": t, "status": s, "reason": reason}
}

// copyStatus preserves an object's status across an Apply.
//
// On a real API server status is a subresource: an update to spec does not
// clear it, and a provider that expected otherwise would report a running
// workload as pending after every no-op reconcile. Reproducing that here keeps
// the provider honest about which half of an object it owns.
func copyStatus(dst, src runtime.Object) {
	switch d := dst.(type) {
	case *appsv1.Deployment:
		if s, ok := src.(*appsv1.Deployment); ok {
			d.Status = s.Status
		}
	case *unstructured.Unstructured:
		if s, ok := src.(*unstructured.Unstructured); ok {
			if st, found := s.Object["status"]; found {
				d.Object["status"] = st
			}
		}
	}
}
