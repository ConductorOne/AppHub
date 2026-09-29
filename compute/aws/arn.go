// Copyright 2026 ConductorOne, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import "strings"

// This file composes the ARNs this provider has to name in a policy document.
//
// It exists because a bucket ARN is the one identifier S3 does not report. A
// repository ARN and a role ARN are read back from the service -- see
// [RepositoryRecord.ARN] for why that matters -- but no S3 call returns
// "arn:aws:s3:::name", so a policy that names a bucket has to build it.

// partitionFor returns the ARN partition a region belongs to.
//
// Derived from the region rather than configured, because the two cannot
// disagree: a partition is a property of the region, and an operator who could
// set it separately could set it wrongly, producing a policy that names a
// resource in a partition their credentials cannot reach. The failure would
// surface as an authorization error against a correct-looking document.
//
// The default is the commercial partition, which is right for every region
// outside the three special cases and stays right when AWS adds a region.
func partitionFor(region string) string {
	switch {
	case strings.HasPrefix(region, "cn-"):
		return "aws-cn"
	case strings.HasPrefix(region, "us-gov-"):
		return "aws-us-gov"
	case strings.HasPrefix(region, "us-iso"):
		// us-iso-*, us-isob-* and us-isof-* are separate partitions. Grouping
		// them under one name would be wrong, so this returns the one that
		// matches the prefix and nothing else claims to handle the others.
		return "aws-iso"
	default:
		return "aws"
	}
}

// bucketARN composes a general-purpose bucket's ARN.
//
// An S3 bucket ARN carries no account and no region -- the namespace is global,
// which is the same fact that makes a name collision with another account
// possible. That is convenient here: this package holds no account identifier
// and does not need one to name a bucket.
func bucketARN(partition, name string) string {
	return "arn:" + partition + ":s3:::" + name
}

// objectsARN names every object in a bucket.
//
// Separate from [bucketARN] because S3 requires it: the bucket-level actions
// (ListBucket, GetBucketLocation) take the bucket ARN and the object-level ones
// (GetObject, PutObject) take the "/*" form, and a statement that lists only one
// of the two silently grants nothing for half its actions.
func objectsARN(partition, name string) string {
	return bucketARN(partition, name) + "/*"
}
