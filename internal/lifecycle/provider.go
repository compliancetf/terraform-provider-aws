package lifecycle

import (
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/hook"
)

// Region names of the partitions the provider binds: the RegionRegex of
// aws-sdk-go-v2 partitions.json, narrowed to lower-case letters. The
// aws-us-gov pattern is tried first; the aws pattern matches neither it, an
// ISO region nor an aws-eusc region, which stay not known. Unlike the SDK, a
// region no pattern matches is never aws.
var partitionRegions = []struct {
	partition string
	re        *regexp.Regexp
}{
	{"aws-us-gov", regexp.MustCompile(`^us-gov-[a-z]+-[0-9]+$`)},
	{"aws-cn", regexp.MustCompile(`^cn-[a-z]+-[0-9]+$`)},
	{"aws", regexp.MustCompile(`^(af|ap|ca|eu|il|me|mx|sa|us)-[a-z]+-[0-9]+$`)},
}

// partitionOf maps the upstream provider region to its partition.
// Any other region, an empty one included, is not known:
// provider.partition stays unknown and iam.principals_in_account unresolved
// (fail closed), never aws. shortcut: aws, aws-cn and aws-us-gov only; add
// the ISO and eusc partitions with their region names when a bundle needs
// them.
func partitionOf(region string) (string, bool) {
	for _, p := range partitionRegions {
		if p.re.MatchString(region) {
			if p.partition == "aws" && reservedInfix(region) {
				return "", false
			}
			return p.partition, true
		}
	}
	return "", false
}

// reservedInfix: the second label of an aws-shaped region is gov or iso*
// ("us-gov-1", "us-iso-1"), the label of another partition. The SDK resolves
// such a name to aws; the binding leaves it unknown.
func reservedInfix(region string) bool {
	_, rest, _ := strings.Cut(region, "-")
	label, _, _ := strings.Cut(rest, "-")
	return label == "gov" || strings.HasPrefix(label, "iso")
}

// providerInfo is the provider binding of a Configure: the region and its
// partition, both known only when the region names a partition.
// The account is ownAccount's. provider.region is the provider-level
// region; resourceProvider overrides it per resource.
func providerInfo(region string, known bool) engine.ProviderInfo {
	if !known {
		return engine.ProviderInfo{}
	}
	p, ok := partitionOf(region)
	if !ok {
		return engine.ProviderInfo{}
	}
	return engine.ProviderInfo{Region: region, RegionKnown: true, Partition: p, PartitionKnown: true}
}

// accountIDRe is an AWS account id: twelve decimal digits.
var accountIDRe = regexp.MustCompile(`^[0-9]{12}$`)

// ownAccount is provider.account_id:
// the one account id the upstream config declares in allowed_account_ids,
// which the upstream provider checks its credentials against at Configure.
// The proxy never calls STS. No id, several ids, an unknown set, a malformed
// id, or skip_requesting_account_id set (the upstream check then has no
// account to compare) leave it unknown, never assumed.
func ownAccount(req *hook.ConfigureRequest) (string, bool) {
	if !req.AccountKnown || req.SkipAccountID || !accountIDRe.MatchString(req.AccountID) {
		return "", false
	}
	return req.AccountID, true
}

// resourceProvider is p for one evaluation of a: hashicorp/aws
// v6 lets a resource set its own region argument, and the resource then
// lives there, so provider.region and provider.partition bind to it. The
// region is read from the config, or from the resource value when there is
// no config (apply's post-state check reads the new state) or a is a
// deletion guard (RegionFromResource: deletion guards bind the prior
// region, also on a replace whose config names a new one). A known region binds with its partition when partitionOf maps it
// (else the partition is unknown); an unknown or empty region leaves both
// unknown, never the provider value; a null region, or a schema with no
// string region attribute, keeps p. The account is p's.
func resourceProvider(p engine.ProviderInfo, a *engine.Activation) engine.ProviderInfo {
	src := a.Config
	if a.RegionFromResource || src.IsNull() {
		src = a.Resource
	}
	r, ok := regionAttr(src)
	if !ok || r.IsNull() {
		return p
	}
	out := engine.ProviderInfo{AccountID: p.AccountID, AccountKnown: p.AccountKnown}
	var s string
	if !r.IsKnown() || r.As(&s) != nil || s == "" {
		return out
	}
	out.Region, out.RegionKnown = s, true
	out.Partition, out.PartitionKnown = partitionOf(s)
	return out
}

// regionAttr is the region attribute of v, an object whose type has a string
// region attribute; it is unknown when v is. ok is false for any other v.
func regionAttr(v tftypes.Value) (tftypes.Value, bool) {
	unknown := tftypes.NewValue(tftypes.String, tftypes.UnknownValue)
	obj, isObj := v.Type().(tftypes.Object)
	if !isObj {
		return unknown, false
	}
	if t, has := obj.AttributeTypes["region"]; !has || !t.Is(tftypes.String) {
		return unknown, false
	}
	if !v.IsKnown() {
		return unknown, true
	}
	if v.IsNull() {
		return unknown, false
	}
	var m map[string]tftypes.Value
	if v.As(&m) != nil {
		return unknown, true // a region attribute that cannot be read: unknown
	}
	return m["region"], true
}
