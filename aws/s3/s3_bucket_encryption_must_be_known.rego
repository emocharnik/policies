package terraform

import input.tfplan as tfplan
import data.helpers.utils

# Deny S3 buckets with unknown encryption config when no separate encryption resource exists
# Prevents deploying buckets with unpredictable encryption settings
deny[reason] {
    r := utils.s3_buckets[_]
    r.change.after_unknown.server_side_encryption_configuration == true
    count(utils.s3_bucket_encryption_configs) == 0
    reason := sprintf(
        "%s: server-side encryption configuration is unknown at plan time and must be explicitly set with sse_algorithm from %v (either inline or via aws_s3_bucket_server_side_encryption_configuration)",
        [r.address, utils.allowed_sse_algorithms]
    )
}

