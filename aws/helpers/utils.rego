package helpers.utils

import input.tfplan as tfplan

# Allowed values
allowed_acls := ["private"]
allowed_sse_algorithms := ["aws:kms", "AES256"]

# Get all S3 buckets
s3_buckets[r] {
    r := tfplan.resource_changes[_]
    r.type == "aws_s3_bucket"
}

# Get all S3 bucket encryption configurations (separate resource in modern AWS provider)
s3_bucket_encryption_configs[r] {
    r := tfplan.resource_changes[_]
    r.type == "aws_s3_bucket_server_side_encryption_configuration"
}

# Get all S3 bucket ownership controls (used to enforce BucketOwnerEnforced which disables ACLs)
s3_bucket_ownership_controls[r] {
    r := tfplan.resource_changes[_]
    r.type == "aws_s3_bucket_ownership_controls"
}

# Helper function to check if a bucket has BucketOwnerEnforced (which disables ACLs)
has_bucket_owner_enforced(bucket_address) {
    ownership := s3_bucket_ownership_controls[_]
    rule := ownership.change.after.rule[_]
    rule.object_ownership == "BucketOwnerEnforced"
}

# Helper function to check if array contains element
array_contains(arr, elem) {
    arr[_] = elem
}

