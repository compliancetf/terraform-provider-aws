// Package testdata holds shared fixtures. The go tool skips testdata
// directories in ./... patterns, so regenerate with:
//
//	go generate ./testdata/generate.go
//
// Output is reproducible: running it twice yields the same bytes
// (TestBuildReproducible in cmd/ctfbundle checks the committed files).
//
// bundles/release-iam/iam-actions.json is release content, built by
// cmd/iamcatalog from the AWS service reference snapshot whose file digests
// iam/service-reference-<retrieved>.sha256 pins (its sha256 is the catalog's
// "snapshot"). To refresh it, download every service document listed at
// https://servicereference.us-east-1.amazonaws.com/ into a new empty <dir>,
// then run from the repo root:
//
//	go run ./cmd/iamcatalog -source <dir> -retrieved YYYY-MM-DD -out testdata/bundles/release-iam/iam-actions.json
//	(cd <dir> && shasum -a 256 *.json) > testdata/iam/service-reference-YYYY-MM-DD.sha256
//
// and regenerate. A catalog change is a bundle release.
package testdata

//go:generate go run -tags ctftest ../cmd/ctfbundle build -src bundles/bobthecorp-soc2-sim -key test:bundle -out bundles/bobthecorp-soc2-sim/good.tar.gz
//go:generate go run -tags ctftest ../cmd/ctfbundle build -src bundles/swap-graph/a -key test:bundle -out bundles/swap-graph/a.tar.gz
//go:generate go run -tags ctftest ../cmd/ctfbundle build -src bundles/swap-graph/b -key test:bundle -out bundles/swap-graph/b.tar.gz
//go:generate go run -tags ctftest ../cmd/ctfbundle build -src ../internal/bundle/testdata/contentdigest/coverable-from-build-json -key test:bundle -out ../internal/bundle/testdata/contentdigest/coverable-from-build-json/bundle.tar.gz
//go:generate go run -tags ctftest ../cmd/ctfbundle build -src ../internal/bundlegen/testdata/contentdigest/base -key test:bundle -out ../internal/bundlegen/testdata/contentdigest/base/bundle.tar.gz
//go:generate go run -tags ctftest ../cmd/ctfbundle build -src ../internal/bundlegen/testdata/contentdigest/swap-graph -key test:bundle -out ../internal/bundlegen/testdata/contentdigest/swap-graph/bundle.tar.gz
//go:generate go run -tags ctftest ../cmd/ctfbundle build -src ../internal/bundlegen/testdata/contentdigest/coverable-changed -key test:bundle -out ../internal/bundlegen/testdata/contentdigest/coverable-changed/bundle.tar.gz
//go:generate go run -tags ctftest ../cmd/ctfbundle tamper -src bundles/bobthecorp-soc2-sim -key test:bundle -out bundles/bobthecorp-soc2-sim
//go:generate go run -tags ctftest ../cmd/ctfbundle sigbugs -src bundles/bobthecorp-soc2-sim -out ../internal/bundle/testdata/sigbugs
//go:generate go run -tags ctftest ../cmd/ctfbundle sign -type profile -in profiles/src/bobthecorp-permissive.json -key test:profile -out profiles/bobthecorp-permissive.dsse.json
//go:generate go run -tags ctftest ../cmd/ctfbundle build -src bundles/release-iam -key test:bundle -out bundles/release-iam.tar.gz
