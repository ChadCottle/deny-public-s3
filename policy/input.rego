package s3

deny_public_s3 contains bucket if {
    bucket := input
    bucket.resource_type == "aws_s3_bucket"
    bucket.acl == "public-read"
}
