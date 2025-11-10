package terraform

import input.tfplan as tfplan

# Deny S3 buckets without encryption when no separate encryption resource exists
# Ensures all buckets have server-side encryption configured
deny[reason] {
    r := s3_buckets[_]
    not r.change.after_unknown.server_side_encryption_configuration
    count(r.change.after.server_side_encryption_configuration) == 0
    count(s3_bucket_encryption_configs) == 0
    reason := sprintf(
        "%s: requires server-side encryption with expected sse_algorithm to be one of %v (either inline or via aws_s3_bucket_server_side_encryption_configuration)",
        [r.address, allowed_sse_algorithms]
    )
}

