// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

// renderSpec produces a canonical form of everything about an object except its
// status, so that [MemoryCluster.Apply] can tell a real change from a no-op the
// way a generation bump does on a real server.
//
// It is never shown to anybody: it contains a Secret's data.
func renderSpec(obj runtime.Object) string {
	c := obj.DeepCopyObject()
	switch v := c.(type) {
	case *appsv1.Deployment:
		v.Status = appsv1.DeploymentStatus{}
		v.ResourceVersion, v.Generation = "", 0
	case *batchv1.CronJob:
		v.Status = batchv1.CronJobStatus{}
		v.ResourceVersion, v.Generation = "", 0
	case *corev1.Secret:
		v.ResourceVersion, v.Generation = "", 0
	case *corev1.ServiceAccount:
		v.ResourceVersion, v.Generation = "", 0
	case *corev1.Service:
		v.Status = corev1.ServiceStatus{}
		v.ResourceVersion, v.Generation = "", 0
	case *corev1.ConfigMap:
		v.ResourceVersion, v.Generation = "", 0
	case *networkingv1.NetworkPolicy:
		v.ResourceVersion, v.Generation = "", 0
	case *networkingv1.Ingress:
		v.Status = networkingv1.IngressStatus{}
		v.ResourceVersion, v.Generation = "", 0
	case *unstructured.Unstructured:
		delete(v.Object, "status")
		v.SetResourceVersion("")
		v.SetGeneration(0)
	}
	b, err := json.Marshal(c)
	if err != nil {
		// A k8s API object that will not marshal is a programming error here,
		// not a runtime condition; degrade to something unequal rather than
		// panicking inside a lock.
		return fmt.Sprintf("unmarshalable:%T:%v", c, err)
	}
	return string(b)
}

// templateHash is the provider's [compute.ServiceStatus.Revision]: a digest of
// the pod template, which is Kubernetes' own notion of "the deployed version of
// the spec" and is what a ReplicaSet's pod-template-hash label carries.
//
// Deliberately not the object's generation. A generation changes when replicas
// change, and [compute.ServiceStatus.Revision] is documented as changing when
// the effective configuration changes so a caller can tell a rollout from a
// scale — which is exactly the distinction a template hash draws and a
// generation does not.
func templateHash(t corev1.PodTemplateSpec) string {
	b, err := json.Marshal(t)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])[:10]
}

// renderObject is the operator-facing, redaction-safe rendering used by the
// conformance suite's Rendered hook.
//
// The rule it enforces is the one that matters for a repository going public:
// a Secret's data never appears, and neither does anything derived from it. A
// workload's secret environment shows as the reference the kubelet will
// resolve, which is the whole point of secretKeyRef.
func renderObject(key objectKey, obj runtime.Object) string {
	head := fmt.Sprintf("%s: ", key)
	fields := []string{}
	if l := metaAnnotations(obj)[annotationLabels]; l != "" {
		fields = append(fields, l)
	}
	switch v := obj.(type) {
	case *corev1.ServiceAccount:
		var pull []string
		for _, s := range v.ImagePullSecrets {
			pull = append(pull, s.Name)
		}
		if len(pull) > 0 {
			fields = append(fields, "imagePullSecrets="+strings.Join(pull, ","))
		}
	case *corev1.Secret:
		// Keys only. The values are the material.
		keys := make([]string, 0, len(v.Data))
		for k := range v.Data {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fields = append(fields, "type="+string(v.Type), "keys="+strings.Join(keys, ","))
	case *corev1.ConfigMap:
		keys := make([]string, 0, len(v.BinaryData))
		for k := range v.BinaryData {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fields = append(fields, "keys="+strings.Join(keys, ","))
	case *appsv1.Deployment:
		replicas := int32(1)
		if v.Spec.Replicas != nil {
			replicas = *v.Spec.Replicas
		}
		fields = append(fields, fmt.Sprintf("replicas=%d", replicas))
		fields = append(fields, renderPodSpec(v.Spec.Template.Spec)...)
	case *batchv1.CronJob:
		fields = append(fields, "schedule="+v.Spec.Schedule)
		if v.Spec.TimeZone != nil {
			fields = append(fields, "timezone="+*v.Spec.TimeZone)
		}
		suspended := v.Spec.Suspend != nil && *v.Spec.Suspend
		fields = append(fields, fmt.Sprintf("suspend=%t", suspended))
		fields = append(fields, renderPodSpec(v.Spec.JobTemplate.Spec.Template.Spec)...)
	case *corev1.Service:
		var ports []string
		for _, p := range v.Spec.Ports {
			ports = append(ports, fmt.Sprintf("%d/%s", p.Port, strings.ToLower(string(p.Protocol))))
		}
		fields = append(fields, "type="+string(v.Spec.Type), "ports="+strings.Join(ports, ","))
	case *networkingv1.NetworkPolicy:
		fields = append(fields, "policyTypes="+joinPolicyTypes(v.Spec.PolicyTypes))
		fields = append(fields, "ingressFrom="+renderNetworkPolicyIngress(v.Spec.Ingress))
	case *networkingv1.Ingress:
		var rules []string
		for _, r := range v.Spec.Rules {
			paths := []string{}
			if r.HTTP != nil {
				for _, p := range r.HTTP.Paths {
					paths = append(paths, p.Path)
				}
			}
			rules = append(rules, r.Host+strings.Join(paths, "|"))
		}
		fields = append(fields, "rules="+strings.Join(rules, ","))
		var tls []string
		for _, t := range v.Spec.TLS {
			tls = append(tls, t.SecretName)
		}
		fields = append(fields, "tlsSecrets="+strings.Join(tls, ","))
	case *unstructured.Unstructured:
		fields = append(fields, renderUnstructured(v)...)
	}
	return head + strings.Join(fields, " ")
}

func joinPolicyTypes(ts []networkingv1.PolicyType) string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, string(t))
	}
	return strings.Join(out, ",")
}

// renderNetworkPolicyIngress renders the compiled reachability rules, which is
// what makes "a rule removed from the spec is gone from the substrate"
// checkable at all.
func renderNetworkPolicyIngress(rules []networkingv1.NetworkPolicyIngressRule) string {
	var out []string
	for _, r := range rules {
		var peers []string
		for _, p := range r.From {
			switch {
			case p.IPBlock != nil:
				peers = append(peers, p.IPBlock.CIDR)
			case p.NamespaceSelector != nil || p.PodSelector != nil:
				peers = append(peers, renderSelectorPeer(p))
			}
		}
		var ports []string
		for _, p := range r.Ports {
			if p.Port != nil {
				ports = append(ports, p.Port.String())
			}
		}
		out = append(out, strings.Join(peers, "+")+":"+strings.Join(ports, "|"))
	}
	return strings.Join(out, ",")
}

func renderSelectorPeer(p networkingv1.NetworkPolicyPeer) string {
	parts := []string{}
	if p.NamespaceSelector != nil {
		parts = append(parts, "ns("+sortedPairs(p.NamespaceSelector.MatchLabels)+")")
	}
	if p.PodSelector != nil {
		parts = append(parts, "pod("+sortedPairs(p.PodSelector.MatchLabels)+")")
	}
	return strings.Join(parts, "/")
}

func renderPodSpec(spec corev1.PodSpec) []string {
	var fields []string
	if spec.ServiceAccountName != "" {
		fields = append(fields, "serviceAccount="+spec.ServiceAccountName)
	}
	for _, c := range spec.Containers {
		fields = append(fields, "image="+c.Image)
		if r, ok := c.Resources.Requests[corev1.ResourceCPU]; ok {
			fields = append(fields, "cpuRequest="+r.String())
		}
		if r, ok := c.Resources.Requests[corev1.ResourceMemory]; ok {
			fields = append(fields, "memRequest="+r.String())
		}
		for _, e := range c.Env {
			switch {
			case e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil:
				// The reference, never the value.
				fields = append(fields, fmt.Sprintf("%s=secretKeyRef(%s/%s)",
					e.Name, e.ValueFrom.SecretKeyRef.Name, e.ValueFrom.SecretKeyRef.Key))
			default:
				fields = append(fields, e.Name+"="+e.Value)
			}
		}
	}
	return fields
}

func renderUnstructured(u *unstructured.Unstructured) []string {
	var fields []string
	fields = append(fields, "apiVersion="+u.GetAPIVersion())
	switch u.GetKind() {
	case kindPostgresCluster:
		if v, ok, _ := unstructured.NestedString(u.Object, "spec", "imageName"); ok {
			fields = append(fields, "image="+v)
		}
		if v, ok, _ := unstructured.NestedInt64(u.Object, "spec", "instances"); ok {
			fields = append(fields, fmt.Sprintf("instances=%d", v))
		}
		for _, key := range []string{"cpu", "memory"} {
			if v, ok, _ := unstructured.NestedString(u.Object, "spec", "resources", "requests", key); ok {
				fields = append(fields, "request."+key+"="+v)
			}
			if v, ok, _ := unstructured.NestedString(u.Object, "spec", "resources", "limits", key); ok {
				fields = append(fields, "limit."+key+"="+v)
			}
		}
		if v, ok, _ := unstructured.NestedString(u.Object, "spec", "bootstrap", "initdb", "secret", "name"); ok {
			// The name of the Secret holding the admin password, never its
			// contents. CloudNativePG reads it; apphub does not.
			fields = append(fields, "adminSecret="+v)
		}
		if v := u.GetAnnotations()[annotationCapacityUnits]; v != "" {
			fields = append(fields, "capacity="+v)
		}
	case kindGateway:
		listeners, _, _ := unstructured.NestedSlice(u.Object, "spec", "listeners")
		var out []string
		for _, l := range listeners {
			m, ok := l.(map[string]any)
			if !ok {
				continue
			}
			port, _, _ := unstructured.NestedInt64(m, "port")
			proto, _, _ := unstructured.NestedString(m, "protocol")
			desc := fmt.Sprintf("%d/%s", port, listenerLabel(proto))
			if refs, ok, _ := unstructured.NestedSlice(m, "tls", "certificateRefs"); ok && len(refs) > 0 {
				if first, ok := refs[0].(map[string]any); ok {
					name, _, _ := unstructured.NestedString(first, "name")
					desc += "(cert=" + name + ")"
				}
			}
			out = append(out, desc)
		}
		fields = append(fields, "listeners="+strings.Join(out, ","))
	case kindHTTPRoute:
		hosts, _, _ := unstructured.NestedStringSlice(u.Object, "spec", "hostnames")
		fields = append(fields, "hostnames="+strings.Join(hosts, ","))
	}
	return fields
}

// listenerLabel names a Gateway listener protocol in the form the conformance
// suite looks for, so that "the plaintext listener is gone" is observable.
func listenerLabel(protocol string) string {
	if protocol == protocolHTTPS {
		return "tls"
	}
	return "plaintext"
}
