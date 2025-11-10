package terraform

import input.tfplan as tfplan

# Deny S3 buckets with non-private ACL unless using BucketOwnerEnforced
# Ensures buckets don't have public or other insecure ACL settings
deny[reason] {
    r := s3_buckets[_]
    not r.change.after_unknown.acl
    acl := r.change.after.acl
    not array_contains(allowed_acls, acl)
    not has_bucket_owner_enforced(r.address)
    reason := sprintf(
        "%s: ACL %q is not allowed. Use one of %v or BucketOwnerEnforced ownership controls",
        [r.address, acl, allowed_acls]
    )
}

