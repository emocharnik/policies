package terraform

import input.tfplan as tfplan
import data.helpers.utils

# Validate SSE algorithm for inline encryption configuration on aws_s3_bucket
# Ensures only approved encryption algorithms (aws:kms or AES256) are used
deny contains reason if {
    r := utils.s3_buckets[_]
    not r.change.after_unknown.server_side_encryption_configuration
    sse_configuration := r.change.after.server_side_encryption_configuration[_]
    apply_sse_by_default := sse_configuration.rule[_].apply_server_side_encryption_by_default[_]
    not utils.array_contains(utils.allowed_sse_algorithms, apply_sse_by_default.sse_algorithm)
    reason := sprintf(
        "%s: expected sse_algorithm to be one of %v",
        [r.address, utils.allowed_sse_algorithms]
    )
}

