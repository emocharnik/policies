version = "v1"

# ACL policies - ensure buckets don't have public or insecure access
policy "s3_bucket_acl_must_be_known_or_disabled" {
  enabled           = true
  enforcement_level = "hard-mandatory"
}

policy "s3_bucket_acl_must_be_private" {
  enabled           = true
  enforcement_level = "hard-mandatory"
}

# Encryption policies - ensure all buckets are encrypted at rest
policy "s3_bucket_encryption_must_be_known" {
  enabled           = true
  enforcement_level = "hard-mandatory"
}

policy "s3_bucket_encryption_must_be_enabled" {
  enabled           = true
  enforcement_level = "hard-mandatory"
}

policy "s3_bucket_encryption_algorithm_approved_inline" {
  enabled           = true
  enforcement_level = "hard-mandatory"
}

policy "s3_bucket_encryption_algorithm_approved_separate" {
  enabled           = true
  enforcement_level  = "soft-mandatory"
}
