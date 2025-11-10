package terraform

import input.tfplan as tfplan

# Deny S3 buckets with unknown ACL at plan time unless using BucketOwnerEnforced
# This prevents buckets from being created with unpredictable ACL settings
deny[reason] {
    r := s3_buckets[_]
    r.change.after_unknown.acl == true
    not has_bucket_owner_enforced(r.address)
    reason := sprintf(
        "%s: ACL is unknown at plan time and cannot be validated. Please explicitly set ACL to one of %v or use BucketOwnerEnforced ownership controls",
        [r.address, allowed_acls]
    )
}

