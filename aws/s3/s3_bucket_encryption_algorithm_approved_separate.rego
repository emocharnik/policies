package terraform

import input.tfplan as tfplan
import data.helpers.utils

# Validate SSE algorithm for separate aws_s3_bucket_server_side_encryption_configuration resources
# Ensures only approved encryption algorithms (aws:kms or AES256) are used in modern AWS provider configurations
deny contains reason if {
    encryption := utils.s3_bucket_encryption_configs[_]
    apply_sse_by_default := encryption.change.after.rule[_].apply_server_side_encryption_by_default[_]
    not utils.array_contains(utils.allowed_sse_algorithms, apply_sse_by_default.sse_algorithm)
    reason := sprintf(
        "%s: expected sse_algorithm to be one of %v",
        [encryption.address, utils.allowed_sse_algorithms]
    )
}

