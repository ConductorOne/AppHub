## USOSS-15 — not reading material you have fetched is not the same as not fetching it

`compute.SecretStore.Describe` exists on the understanding that it is a metadata
read rather than a read-back. The Kubernetes implementation honoured that in
intent and not in effect: it called `Cluster.Get`, which fetches and
deserializes the whole `corev1.Secret` — every value in `Data` — and then
declined to look at it.

Its comment said so proudly: *"It never touches sec.Data."* True, and beside the
point. The material had already crossed the wire and entered the process. The
property the operation exists to deliver is **least exposure**, not good
manners.

### The remedy is a different verb, and it is required rather than optional

`Cluster` gains `GetMetadata`, returning `*metav1.PartialObjectMetadata`.
`ClientCluster` implements it with client-go's metadata client, which sends the
`PartialObjectMetadata` Accept header so the API server projects the object
server-side and the values never leave the cluster. `MemoryCluster` implements it
by building a `PartialObjectMetadata` from the object's meta alone — it
necessarily already holds the object, but it hands no value out.

**It is required, not optional like `Watcher`.** A substrate that could not do it
would make `Describe` fall back to `Get`, and a security property with a fallback
is a security property with a bypass. A `ClientCluster` built with no metadata
client therefore **fails the call**, naming the field to set, rather than
widening it. The production constructor builds one, so the refusal is reachable
only by a caller that assembled the cluster by hand.

### The control is written against the substrate, not the function

`TestDescribeNeverReachesTheValueBearingRead` wraps the cluster and counts which
read verb was reached and whether the value-bearing one returned a payload. It
asserts zero `Get` calls and at least one `GetMetadata`.

That distinction is the reason the first version passed review's earlier rounds:
a control that checked what `Describe` **returned** would have been satisfied by
the defective implementation, because the return value was always clean. The
question is not what the function did with the material — it is whether the
material arrived.

It also carries its own instrument check: before resetting the counters it calls
`Get` once and requires the wrapper to have observed a payload. Without that, the
assertion passes on a wrapper that observes nothing.

### The general form

Two rounds of this project have now turned on the same distinction: a claim about
what a reader *does* with something, versus a property of what it *has*. A
redacting type kept its mask beside the material and was defended as *"a generic
dumper does not XOR field pairs"*. This kept the material beside the metadata and
was defended as *"it never touches Data"*.

**Both are claims about behaviour dressed as claims about structure.** The fix in
both cases was to stop having the thing at all.
