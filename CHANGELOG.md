## 6.71.0 (October 29, 2026)

NOTES:

* pin: hashicorp/aws 6.71.0 ([#35](https://github.com/compliancetf/terraform-provider-aws/pull/35))

FEATURES:

* bundlegen: Pin graph control reads in the schema-compat digest and release checks ([#25](https://github.com/compliancetf/terraform-provider-aws/pull/25))
* cis: Make embedded CIS controls exemptible and rename the EBS encryption control to its catalog id ([#34](https://github.com/compliancetf/terraform-provider-aws/pull/34))
* evidence: Record read_digest when a baseline key file is set ([#31](https://github.com/compliancetf/terraform-provider-aws/pull/31))
* release: Backfill releases for older hashicorp/aws versions ([#14](https://github.com/compliancetf/terraform-provider-aws/pull/14))
* release: Ship the embedded CIS bundle as a release asset ([#21](https://github.com/compliancetf/terraform-provider-aws/pull/21))

ENHANCEMENTS:

* wrapper: Drop the unused evidence_sink setting ([#23](https://github.com/compliancetf/terraform-provider-aws/pull/23))

BUG FIXES:

* bundlegen: Skip graph controls in verify and diffcheck instead of failing the bundle ([#37](https://github.com/compliancetf/terraform-provider-aws/pull/37))
* ci: Let the proto drift check fetch the Go toolchain a source needs ([#17](https://github.com/compliancetf/terraform-provider-aws/pull/17))
* ctfbundle: Make the bundle staleness check and the root-swap test pass on CI runners ([#30](https://github.com/compliancetf/terraform-provider-aws/pull/30))
* deps: Grpc 1.85.0 (GO-2026-6443) ([#18](https://github.com/compliancetf/terraform-provider-aws/pull/18))
* exceptions: Ignore the profile coverable list; only the bundle decides coverability ([#20](https://github.com/compliancetf/terraform-provider-aws/pull/20))
* fsutil: Owner and ACL checks for cache and evidence directories on Windows ([#29](https://github.com/compliancetf/terraform-provider-aws/pull/29))
* iampolicy: Calibrate IAM decode and match cost rates against the action catalog ([#26](https://github.com/compliancetf/terraform-provider-aws/pull/26))
* iampolicy: Match account root and role sessions in iam.principal_is ([#38](https://github.com/compliancetf/terraform-provider-aws/pull/38))
* plan: Warn a pending grant or self-service exemption only when the run can use that kind ([#32](https://github.com/compliancetf/terraform-provider-aws/pull/32))
* schemadiff: Check the companion_expr reads of graph controls ([#39](https://github.com/compliancetf/terraform-provider-aws/pull/39))
* trust: Derive the air-gap clock from accepted floor statements only ([#28](https://github.com/compliancetf/terraform-provider-aws/pull/28))
* upstream: Accept a HashiCorp signature valid now, at signing or at the key's binding time ([#15](https://github.com/compliancetf/terraform-provider-aws/pull/15))

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
