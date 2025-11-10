package terraform

import input.tfplan as tfplan

# Validate SSE algorithm for separate aws_s3_bucket_server_side_encryption_configuration resources
# Ensures only approved encryption algorithms (aws:kms or AES256) are used in modern AWS provider configurations
deny[reason] {
    encryption := s3_bucket_encryption_configs[_]
    apply_sse_by_default := encryption.change.after.rule[_].apply_server_side_encryption_by_default[_]
    not array_contains(allowed_sse_algorithms, apply_sse_by_default.sse_algorithm)
    reason := sprintf(
        "%s: expected sse_algorithm to be one of %v",
        [encryption.address, allowed_sse_algorithms]
    )
}

