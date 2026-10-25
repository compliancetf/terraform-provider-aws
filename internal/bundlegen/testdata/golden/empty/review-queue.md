# Review queue

3 content intents emit no control until an authored override exists in provider/controls/<id>.yaml.

## 1. `iam_bobthecorp_no_kms_wildcard`

- `E_REVIEW_PENDING iam_bobthecorp_no_kms_wildcard -: no_intent: no intent for a disposition with content intents`

## 2. `rds_bobthecorp_storage_encrypted`

- `E_REVIEW_PENDING rds_bobthecorp_storage_encrypted -: no_intent: no intent for a disposition with content intents`

## 3. `s3_bobthecorp_versioning_on`

- `E_REVIEW_PENDING s3_bobthecorp_versioning_on aws_s3_bucket_versioning: path: versioning_configuration[0].status equals_any: versioning_configuration is not in the schema`
