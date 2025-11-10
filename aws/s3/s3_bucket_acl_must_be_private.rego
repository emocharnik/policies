package terraform

import input.tfplan as tfplan
import data.helpers.utils

# Deny S3 buckets with non-private ACL unless using BucketOwnerEnforced
# Ensures buckets don't have public or other insecure ACL settings
deny contains reason if {
    r := utils.s3_buckets[_]
    not r.change.after_unknown.acl
    acl := r.change.after.acl
    not utils.array_contains(utils.allowed_acls, acl)
    not utils.has_bucket_owner_enforced(r.address)
    reason := sprintf(
        "%s: ACL %q is not allowed. Use one of %v or BucketOwnerEnforced ownership controls",
        [r.address, acl, utils.allowed_acls]
    )
}

