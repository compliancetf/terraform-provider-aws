## 6.70.0 (October 25, 2026)

NOTES:

* pin: hashicorp/aws 6.70.0 ([#12](https://github.com/compliancetf/terraform-provider-aws/pull/12))

## 6.69.1 (October 25, 2026)

NOTES:

* pin: hashicorp/aws 6.69.1 ([#10](https://github.com/compliancetf/terraform-provider-aws/pull/10))

## 6.69.0-compliancetf.2 (October 25, 2026)

FEATURES:

* diagnostics: Shorter control diagnostics with a docs link ([#7](https://github.com/compliancetf/terraform-provider-aws/pull/7))

## 6.69.0-compliancetf.1 (October 25, 2026)

ENHANCEMENTS:

* upstream: Share the verified upstream copy and schema across starts ([#5](https://github.com/compliancetf/terraform-provider-aws/pull/5))

## 6.69.0 (October 25, 2026)

NOTES:

* provider: First release from this repository; compliancetf/aws X.Y.Z proxies hashicorp/aws X.Y.Z
* pin: hashicorp/aws 6.69.0 ([#1](https://github.com/compliancetf/terraform-provider-aws/pull/1))
* provider: Rebuilt on October 25, 2026 from master, so 6.69.0 also carries the changes of 6.69.0-compliancetf.1, 6.69.0-compliancetf.2, [#8](https://github.com/compliancetf/terraform-provider-aws/pull/8) and [#9](https://github.com/compliancetf/terraform-provider-aws/pull/9). Its archives changed, so a lock file that recorded the earlier 6.69.0 hashes fails `terraform init`, with `-upgrade` too: remove the `registry.compliance.tf/compliancetf/aws` block from `.terraform.lock.hcl` and run `terraform init`, or move to 6.69.1 or later
