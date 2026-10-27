package bundlegen

import (
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"math"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/celeng"
	"github.com/compliancetf/terraform-provider-aws/internal/iampolicy"
)

// Options carry generator provenance written to build.json.
type Options struct {
	GeneratorVersion string
	GeneratorCommit  string
	// UpstreamPin is the exact hashicorp/aws version of pins.json
	// (upstream.Pins.Version), the last of Releases.
	UpstreamPin string
	// Releases is releases.json: build.json provider and upstream
	// version_range derive from its floor (VersionRange), and the controls
	// must hold on the schema of every supported release
	// (Inputs.SupportedSchemas).
	Releases Releases
	// CaseSchema is every case's schema field: the slash-separated relative
	// path the replay runner loads the schema from (the --schema argument).
	CaseSchema string
}

// UpstreamSource is build.json upstream.source.
const UpstreamSource = "hashicorp/aws"

// ProviderAddress is build.json provider.address.
const ProviderAddress = "registry.compliance.tf/compliancetf/aws"

var pinRe = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

// VersionRange derives build.json provider and upstream version_range from
// the release floor: same major, at least the floor, so
// 6.67.0 gives ">= 6.67.0, < 7.0.0". Under version parity release X.Y.Z
// wraps hashicorp/aws X.Y.Z, so both ranges are the same. An empty or non
// x.y.z floor fails E_UPSTREAM_PIN: the generator never emits an open or
// empty range.
func VersionRange(floor string) (string, error) {
	m := pinRe.FindStringSubmatch(floor)
	if m == nil {
		return "", errf("E_UPSTREAM_PIN", "release floor %q is not an exact x.y.z version", floor)
	}
	major, err := strconv.Atoi(m[1])
	if err != nil || major == math.MaxInt {
		return "", errf("E_UPSTREAM_PIN", "release floor %q: major version out of range", floor)
	}
	return fmt.Sprintf(">= %s, < %d.0.0", floor, major+1), nil
}

// Output maps slash-separated paths under the output directory to file bytes.
type Output struct {
	Files map[string][]byte
	// ReviewQueue lists the E_REVIEW_PENDING ids, also in review-queue.md.
	ReviewQueue []ReviewItem
	// Diffcheck is the diffcheck.json report, nil when diffcheck did not run.
	Diffcheck *DiffcheckReport
}

var snapshotDateRe = regexp.MustCompile(`^snap_([0-9]{8})_`)

func isLocal(d string) bool { return d == "provider-local" || d == "companion-local" }

// build is build.json, the hand-off to ctfbundle build. ContentDigest is
// never read by the provider, which recomputes it from verified bytes, and
// build.json is never a coverability input.
// Files lists the archive files besides controls.json, never null.
type build struct {
	BundleID           string        `json:"bundle_id"`
	Label              string        `json:"label"`
	Catalog            buildCatalog  `json:"catalog"`
	Provider           buildProvider `json:"provider"`
	Upstream           buildUpstream `json:"upstream"`
	SchemaCompatDigest string        `json:"schema_compat_digest"`
	ContentDigest      string        `json:"content_digest"`
	Files              []string      `json:"files"`
	Generator          provenance    `json:"generator"`
	Content            provenance    `json:"content"`
}

// buildProvider is the manifest provider block. Under version parity
// compliancetf/aws X.Y.Z wraps hashicorp/aws X.Y.Z, so its range is the
// upstream range: both start at the release floor.
type buildProvider struct {
	Address      string `json:"address"`
	VersionRange string `json:"version_range"`
}

type buildUpstream struct {
	Source       string `json:"source"`
	VersionRange string `json:"version_range"`
}

// buildCatalog carries the catalog manifest keys plus the bundle.DigestJSON digests
// of the catalog controls.json and provider_dispositions.json; the
// digests stay in build.json, never in the manifest.
type buildCatalog struct {
	SnapshotID         string `json:"snapshot_id"`
	SchemaVersion      string `json:"schema_version"`
	ControlsSHA256     string `json:"controls_sha256"`
	DispositionsSHA256 string `json:"dispositions_sha256"`
}

type provenance struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

// Generate validates the inputs, collects controls per local disposition in
// id order and emits each non-empty bundle as <bundle_id>/controls.json and
// <bundle_id>/build.json, plus <bundle_id>/iam-actions.json when a control
// calls iam.*, and content-lock.json, coverage.json, coverage.md,
// review-queue.md and review-sheet.md for every bundle. Control versions come
// from the content lock (ApplyLock) with bumps.yaml and the authored
// version_bump (MergeBumps). A bundle
// with no control is not emitted: an empty controls.json does not load.
// Each bundle carries the cases of its controls under <id>/cases/
// (controlCases) and the output must verify clean (Verify): a finding fails
// the run with its code, so no bundle ships unverified.
//
// With in.PolicyFixtures set, Diffcheck then runs on the verified output
// (generate step 5) and its report is diffcheck.json. A control id with an
// E_DIFFCHECK_MISMATCH moves to the review queue (reason diffcheck): the
// output is generated again without that id, so it ships in no bundle and
// coverage counts it as not generated. Any other E_ finding fails the run
// with its code; W_ findings are kept in the report (Output.Diffcheck).
// A nil PolicyFixtures skips diffcheck and writes no diffcheck.json; the
// CLI requires the fixtures unless --no-diffcheck is given.
func Generate(in Inputs, opts Options) (*Output, error) {
	out, err := generateOnce(in, opts, nil)
	if err != nil || in.PolicyFixtures == nil {
		return out, err
	}
	rep, err := diffcheckGenerated(out, in)
	if err != nil {
		return nil, err
	}
	// Other E_ findings fail before any id is held: dropping an id must
	// never hide a finding of that id that is not a mismatch.
	if err := diffcheckFailure(rep, "E_DIFFCHECK_MISMATCH"); err != nil {
		return nil, err
	}
	if held := diffcheckHeld(rep); len(held) > 0 {
		if out, err = generateOnce(in, opts, held); err != nil {
			return nil, err
		}
		if rep, err = diffcheckGenerated(out, in); err != nil {
			return nil, err
		}
	}
	if err := diffcheckFailure(rep, ""); err != nil {
		return nil, err
	}
	if out.Files["diffcheck.json"], err = rep.JSON(); err != nil {
		return nil, err
	}
	out.Diffcheck = &rep
	return out, nil
}

// diffcheckFailure fails with every E_ finding of rep except code skip,
// under the first one's code.
func diffcheckFailure(rep DiffcheckReport, skip string) error {
	var code string
	var fails []string
	for _, f := range rep.Findings {
		if strings.HasPrefix(f.Code, "E_") && f.Code != skip {
			code = cmp.Or(code, f.Code)
			fails = append(fails, "bundle "+f.Bundle+": "+f.String())
		}
	}
	if len(fails) > 0 {
		return errf(code, "diffcheck: %s", strings.Join(fails, "; "))
	}
	return nil
}

// diffcheckGenerated runs Diffcheck on a generated output. With no bundle
// emitted there is nothing to compare (Diffcheck would fail E_VERIFY_EMPTY):
// the report says so (W_DIFFCHECK_NOTHING_COMPARED), so an empty report is
// never read as a clean check.
func diffcheckGenerated(out *Output, in Inputs) (DiffcheckReport, error) {
	if !slices.ContainsFunc(slices.Collect(maps.Keys(out.Files)), func(p string) bool { return strings.HasSuffix(p, "/"+bundle.ControlsFile) }) {
		return DiffcheckReport{Findings: []Finding{{Code: "W_DIFFCHECK_NOTHING_COMPARED", Detail: "no bundle was emitted, so no control was compared"}}}, nil
	}
	rep, err := Diffcheck(out, in.Intents, *in.PolicyFixtures, in.DiffAllow, in.Schemas, VerifyEngine())
	if err != nil {
		return DiffcheckReport{}, errf("E_DIFFCHECK", "%v", err)
	}
	return rep, nil
}

// diffcheckHeld returns one diffcheck review item per control id with an
// E_DIFFCHECK_MISMATCH, its detail listing every distinct mismatched case
// (the same control in several bundles mismatches once).
func diffcheckHeld(rep DiffcheckReport) map[string]ReviewItem {
	cases := map[string][]string{}
	for _, f := range rep.Findings {
		if f.Code == "E_DIFFCHECK_MISMATCH" {
			cases[f.Control] = append(cases[f.Control], f.Case+": "+f.Detail)
		}
	}
	held := map[string]ReviewItem{}
	for id, cs := range cases {
		slices.Sort(cs)
		held[id] = ReviewItem{ID: id, Reason: ReviewDiffcheck,
			Detail: "the control disagrees with the content postcondition on " + strings.Join(slices.Compact(cs), "; ")}
	}
	return held
}

// generateOnce is one generation pass; held ids emit no control and are
// queued with their item.
func generateOnce(in Inputs, opts Options, held map[string]ReviewItem) (*Output, error) {
	if err := validate(in); err != nil {
		return nil, err
	}
	if p := opts.CaseSchema; p == "" || path.IsAbs(p) || filepath.IsAbs(p) || strings.Contains(p, `\`) ||
		path.Clean(p) != p || slices.Contains(strings.Split(p, "/"), "..") {
		return nil, errf("E_INPUT", "case schema path %s: want a clean relative slash-separated path without ..", safeName(p))
	}
	older, err := opts.Releases.Older(opts.UpstreamPin)
	if err != nil {
		return nil, err
	}
	versionRange, err := VersionRange(opts.Releases.Floor)
	if err != nil {
		return nil, err
	}
	// In-process callers skip LoadIAMActions; the catalog is checked here.
	var catalog *iampolicy.Catalog
	if in.IAMActions != nil {
		c, err := iampolicy.LoadCatalog(in.IAMActions)
		if err != nil {
			return nil, errf("E_INPUT", "iam-actions.json: %v", err)
		}
		catalog = c
	}
	m := snapshotDateRe.FindStringSubmatch(in.Catalog.Manifest.SnapshotID)
	if m == nil {
		return nil, errf("E_INPUT", "catalog snapshot_id %q has no date", in.Catalog.Manifest.SnapshotID)
	}
	label := m[1] + "." + in.Intents.ContentVersion
	// The catalog digests are of the files LoadCatalog read; in-memory inputs
	// without them fail rather than write a digest of no file.
	if !digestRe.MatchString(in.Catalog.ControlsSHA256) || !digestRe.MatchString(in.Catalog.DispositionsSHA256) {
		return nil, errf("E_INPUT", "catalog controls.json and provider_dispositions.json digests missing: load the export with LoadCatalog")
	}

	intents, err := intentsByID(in.Intents.Policies)
	if err != nil {
		return nil, err
	}
	var cs, autos []bundle.Control
	var queue []ReviewItem
	for _, id := range slices.Sorted(maps.Keys(in.Catalog.Dispositions.Controls)) {
		d := in.Catalog.Dispositions.Controls[id]
		if !isLocal(d.Disposition) {
			continue
		}
		if item, ok := held[id]; ok {
			queue = append(queue, item)
			continue
		}
		// The authored file wins; else intents content goes through the
		// translator, and a review item emits nothing (E_REVIEW_PENDING).
		local := in.Authored[id]
		translated := len(local) == 0 && d.Content == "intents"
		if translated {
			it, ok := intents[id]
			c, item, err := translateID(id, d, it, ok, in.Schemas)
			if err != nil {
				return nil, err
			}
			if item != nil {
				queue = append(queue, *item)
				continue
			}
			local = []bundle.Control{c}
			queue = append(queue, partialTargets(id, local, d, "the content intent on "+c.ResourceType)...)
		} else if len(local) > 0 {
			queue = append(queue, partialTargets(id, local, d, "the authored file")...)
		}
		fw := FrameworkRefs(in.Catalog.Controls[id])
		tools, err := ToolRefs(in.Catalog.Controls[id])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", id, err)
		}
		for _, c := range local {
			c.Message = in.Catalog.Controls[id].Metadata.Name
			c.Severity = cmp.Or(d.Severity, bundle.SeverityMedium)
			c.FrameworkRefs = slices.Clone(fw)
			c.ToolRefs = cloneToolRefs(tools)
			c.ExemptionCoverable = append([]bundle.ExemptionKind{}, d.ExemptionCoverable...) // never null
			slices.Sort(c.ExemptionCoverable)
			cs = append(cs, c)
			if translated {
				autos = append(autos, c)
			}
		}
	}

	bumps, err := MergeBumps(in.Bumps, in.AuthoredBumps, in.Authored)
	if err != nil {
		return nil, err
	}
	cs, lock, err := ApplyLock(in.Lock, bumps, cs)
	if err != nil {
		return nil, err
	}
	// The range admits every supported release: the controls must hold on
	// each one's schema, not only the pin's.
	if err := checkSupported(cs, in.Schemas, in.SupportedSchemas, older); err != nil {
		return nil, err
	}
	translated := map[ControlKey]bool{}
	for i := range autos {
		translated[keyOf(&autos[i])] = true
	}
	cases, err := controlCases(in, cs, translated, opts.CaseSchema)
	if err != nil {
		return nil, err
	}
	lj, err := canonicalJSON(lock)
	if err != nil {
		return nil, err
	}
	sheet, err := ReviewSheet(autos)
	if err != nil {
		return nil, err
	}
	out := &Output{Files: map[string][]byte{
		"review-queue.md": ReviewQueue(queue),
		"review-sheet.md": sheet,
		LockFile:          lj,
	}, ReviewQueue: queue}
	for _, s := range Select(cs, in.Catalog.Controls) {
		data, err := EmitControls(s.Controls)
		if err != nil {
			return nil, fmt.Errorf("bundle %s: %w", s.ID, err)
		}
		compat, err := SchemaCompatDigest(s.Controls, in.Schemas)
		if err != nil {
			return nil, fmt.Errorf("bundle %s: %w", s.ID, err)
		}
		files := []string{}
		if id, err := callsIAM(s.Controls); err != nil {
			return nil, fmt.Errorf("bundle %s: %w", s.ID, err)
		} else if id != "" {
			if catalog == nil {
				return nil, errf("E_IAM_CATALOG_MISSING", "bundle %s: control %s calls iam.* and no iam-actions.json was given", s.ID, id)
			}
			if err := checkCatalogCoverage(s.ID, s.Controls, catalog); err != nil {
				return nil, err
			}
			files = append(files, iampolicy.CatalogFile)
			out.Files[s.ID+"/"+iampolicy.CatalogFile] = in.IAMActions
		}
		out.Files[s.ID+"/controls.json"] = data
		content, err := ContentDigest(s.ID, bundleFiles(out.Files, s.ID))
		if err != nil {
			return nil, err
		}
		bj, err := canonicalJSON(build{
			BundleID:           s.ID,
			Label:              label,
			Catalog:            buildCatalog{in.Catalog.Manifest.SnapshotID, in.Catalog.Manifest.SchemaVersion, in.Catalog.ControlsSHA256, in.Catalog.DispositionsSHA256},
			Provider:           buildProvider{ProviderAddress, versionRange},
			Upstream:           buildUpstream{UpstreamSource, versionRange},
			SchemaCompatDigest: compat,
			ContentDigest:      content,
			Files:              files,
			Generator:          provenance{opts.GeneratorVersion, opts.GeneratorCommit},
			Content:            provenance{in.Intents.ContentVersion, in.Intents.ContentCommit},
		})
		if err != nil {
			return nil, err
		}
		out.Files[s.ID+"/build.json"] = bj
		var bc []Case
		for i := range s.Controls {
			bc = append(bc, cases[keyOf(&s.Controls[i])]...)
		}
		if err := out.AddCases(s.ID, bc); err != nil {
			return nil, err
		}
	}
	cov, md, err := Coverage(in, out.Files)
	if err != nil {
		return nil, err
	}
	out.Files["coverage.json"] = cov
	out.Files["coverage.md"] = md
	if err := verifyGenerated(out, in.Schemas); err != nil {
		return nil, err
	}
	return out, nil
}

// verifyGenerated runs Verify on a generated output with at least one
// bundle and fails with the first finding's code, listing every finding.
func verifyGenerated(out *Output, s Schemas) error {
	if !slices.ContainsFunc(slices.Collect(maps.Keys(out.Files)), func(p string) bool { return strings.HasSuffix(p, "/"+bundle.ControlsFile) }) {
		return nil // nothing emitted: Verify would fail E_VERIFY_EMPTY
	}
	rep, err := Verify(out, s, VerifyEngine())
	if err != nil {
		return errf("E_VERIFY", "%v", err)
	}
	if len(rep.Findings) == 0 {
		return nil
	}
	msgs := make([]string, len(rep.Findings))
	for i, f := range rep.Findings {
		msgs[i] = "bundle " + f.Bundle + ": " + f.String()
	}
	return errf(rep.Findings[0].Code, "verify: %s", strings.Join(msgs, "; "))
}

// bundleFiles returns the files of bundle id in files, by archive file name.
func bundleFiles(files map[string][]byte, id string) map[string][]byte {
	out := map[string][]byte{}
	for p, b := range files {
		if name, ok := strings.CutPrefix(p, id+"/"); ok {
			out[name] = b
		}
	}
	return out
}

// callsIAM returns the first control in cs that calls iam.*, by the check
// the provider uses for iam_catalog_missing, or "" when none does.
func callsIAM(cs []bundle.Control) (string, error) {
	err := celeng.CheckCatalogs(cs, func(*bundle.Control) *iampolicy.Catalog { return nil })
	var d *celeng.LoadDiag
	if errors.As(err, &d) && d.Code == "iam_catalog_missing" {
		return d.ControlID, nil
	}
	return "", err
}

// checkCatalogCoverage fails E_IAM_CATALOG_COVERAGE when a control of
// bundle id looks up an action (iam.grants) or service (iam.grants_all)
// that catalog does not list: the provider would evaluate it ErrUnresolved
// on every resource. Only literal arguments are known here
// (celeng.IAMCatalogRefs).
func checkCatalogCoverage(id string, cs []bundle.Control, catalog *iampolicy.Catalog) error {
	for i := range cs {
		if cs[i].Expr == nil {
			continue
		}
		actions, services, err := celeng.IAMCatalogRefs(*cs[i].Expr)
		if err != nil {
			return errf("E_EMIT", "bundle %s: control %s: %v", id, cs[i].ID, err)
		}
		for _, a := range actions {
			if !catalog.HasAction(a) {
				return errf("E_IAM_CATALOG_COVERAGE", "bundle %s: control %s: iam.grants action %q is not in iam-actions.json", id, cs[i].ID, a)
			}
		}
		for _, svc := range services {
			if !catalog.HasService(svc) {
				return errf("E_IAM_CATALOG_COVERAGE", "bundle %s: control %s: iam.grants_all service %q is not in iam-actions.json", id, cs[i].ID, svc)
			}
		}
	}
	return nil
}

// validate fails closed on the step 1 input errors of the generate algorithm.
func validate(in Inputs) error {
	disp := in.Catalog.Dispositions.Controls
	var missing, unknown []string
	for id := range in.Catalog.Controls {
		if _, ok := disp[id]; !ok {
			missing = append(missing, id)
		}
	}
	for id := range disp {
		if _, ok := in.Catalog.Controls[id]; !ok {
			unknown = append(unknown, id)
		}
	}
	if len(missing)+len(unknown) > 0 {
		slices.Sort(missing)
		slices.Sort(unknown)
		return errf("E_DISPOSITION_COVERAGE", "%d controls without a provider disposition: [%s]; %d dispositions for an unknown control: [%s]",
			len(missing), strings.Join(missing, ", "), len(unknown), strings.Join(unknown, ", "))
	}
	if in.Intents.CatalogSnapshotID != in.Catalog.Manifest.SnapshotID {
		return errf("E_INPUT", "intents exported against catalog %s, catalog export is %s", in.Intents.CatalogSnapshotID, in.Catalog.Manifest.SnapshotID)
	}

	for _, id := range slices.Sorted(maps.Keys(disp)) {
		d := disp[id]
		switch d.Disposition {
		case "provider-local", "companion-local", "graph":
			if len(d.Targets) == 0 {
				return errf("E_DISPOSITION", "%s: %s needs targets", id, d.Disposition)
			}
		case "runtime", "not-expressible":
		default:
			return errf("E_DISPOSITION", "%s: unknown disposition %q", id, d.Disposition)
		}
		for _, t := range d.Targets {
			if err := in.Schemas.checkTarget(t); err != nil {
				return errf("E_SCHEMA_TYPE", "%s: %v", id, err)
			}
		}
		if err := checkCoverable(id, d); err != nil {
			return err
		}
		switch d.Content {
		case "intents", "authored", "none":
		default:
			return errf("E_DISPOSITION", "%s: unknown content %q", id, d.Content)
		}
		if d.Content == "authored" && len(in.Authored[id]) == 0 {
			return errf("E_AUTHORED_MISSING", "%s: content authored but no authored control", id)
		}
	}

	for _, id := range slices.Sorted(maps.Keys(in.Authored)) {
		d, ok := disp[id]
		if !ok || !isLocal(d.Disposition) {
			return errf("E_DISPOSITION", "%s: authored control without a provider-local or companion-local disposition", id)
		}
		for _, c := range in.Authored[id] {
			if c.ID != id || !slices.Contains(d.Targets, Target{Kind: string(c.Kind), Type: c.ResourceType}) {
				return errf("E_DISPOSITION", "%s: authored control %s %s %s is not a disposition target", id, c.ID, c.Kind, c.ResourceType)
			}
		}
	}
	return nil
}

func (s Schemas) checkTarget(t Target) error {
	get := s.kind(bundle.Kind(t.Kind))
	if get == nil {
		return fmt.Errorf("unknown target kind %q", t.Kind)
	}
	if _, ok := get(t.Type); !ok {
		return fmt.Errorf("%s type %s is not in the upstream schema", t.Kind, t.Type)
	}
	return nil
}

// WriteDir writes the output files under dir, which must not exist or be an
// empty real directory: files of an earlier run could otherwise survive and be
// signed. A symlink or special file there, at any depth, fails E_SPECIAL_FILE.
// Every write goes through an os.Root pinned to the directory Lstat sees at
// dir, and every file is created new (O_EXCL), so none follows a symlink or
// opens a FIFO. os.Root follows symlinks inside the root, so the finished
// tree is walked again and any symlink or special file in it fails the run.
// A failed WriteDir may leave a partial dir: the caller deletes it, never
// signs it.
func (o *Output) WriteDir(dir string) error {
	if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return errf("E_OUTPUT", "%v", err)
		}
	}
	root, err := openDirRoot(dir, "E_OUTPUT")
	if err != nil {
		return err
	}
	defer root.Close() //nolint:errcheck // nothing written through it fails on close
	if found, err := walkRoot(root); err != nil {
		return err
	} else if found != "" {
		return errf("E_OUTPUT", "%s must be empty, found %s", dir, found)
	}
	for _, p := range slices.Sorted(maps.Keys(o.Files)) {
		// one level at a time: cases sit at <id>/cases/<control id>/
		parts := strings.Split(p, "/")
		for i := 1; i < len(parts); i++ {
			sub := filepath.FromSlash(strings.Join(parts[:i], "/"))
			if err := root.Mkdir(sub, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
				return errf("E_OUTPUT", "%v", err)
			}
		}
		if err := createFile(root, filepath.FromSlash(p), o.Files[p]); err != nil {
			return err
		}
	}
	_, err = walkRoot(root)
	return err
}

// walkRoot walks root without following symlinks: a symlink or special file
// fails E_SPECIAL_FILE; otherwise it returns the first entry found, or "".
func walkRoot(root *os.Root) (string, error) { return walkRootDir(root, ".", nil, "E_OUTPUT", nil) }

// walkHook, when set by a test, runs before walkRootDir descends into rel.
var walkHook func(rel string)

// walkRootDir walks rel under root. Each directory is opened non-blocking
// and directory-only, and must be the directory listed (listed, nil for the
// pinned root) and what Lstat sees at rel after the open, so an entry
// swapped for a FIFO, another directory or a symlink to the same directory
// after its parent was listed fails E_SPECIAL_FILE instead of blocking or
// being followed. Other failures take code. file, when set, is called with
// each regular file's rel.
func walkRootDir(root *os.Root, rel string, listed fs.FileInfo, code string, file func(rel string) error) (string, error) {
	name := filepath.Join(root.Name(), rel)
	f, err := root.OpenFile(rel, os.O_RDONLY|openNonBlock|openDirectory, 0)
	if err != nil {
		if li, lerr := root.Lstat(rel); lerr == nil && !li.IsDir() {
			return "", errf("E_SPECIAL_FILE", "%s is not a directory", name)
		}
		return "", errf(code, "%v", err)
	}
	defer f.Close() //nolint:errcheck // read-only
	fi, err := f.Stat()
	if err != nil {
		return "", errf(code, "%v", err)
	}
	// The open follows a symlink inside the root: the path must still be
	// that directory itself, not a link to it.
	if after, err := root.Lstat(rel); err != nil || !fi.IsDir() || !after.IsDir() || !os.SameFile(fi, after) ||
		listed != nil && !os.SameFile(fi, listed) {
		return "", errf("E_SPECIAL_FILE", "%s is not the listed directory", name)
	}
	ents, err := f.ReadDir(-1)
	if err != nil {
		return "", errf(code, "%v", err)
	}
	slices.SortFunc(ents, func(a, b fs.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	var found string
	for _, e := range ents {
		p := filepath.Join(rel, e.Name())
		if t := e.Type(); !t.IsDir() && !t.IsRegular() {
			return "", errf("E_SPECIAL_FILE", "%s is not a regular file", filepath.Join(root.Name(), p))
		}
		if found == "" {
			found = filepath.ToSlash(p)
		}
		if !e.IsDir() {
			if file != nil {
				if err := file(p); err != nil {
					return "", err
				}
			}
			continue
		}
		li, err := e.Info()
		if err != nil {
			return "", errf(code, "%v", err)
		}
		if walkHook != nil {
			walkHook(p)
		}
		if _, err := walkRootDir(root, p, li, code, file); err != nil {
			return "", err
		}
	}
	return found, nil
}

// createFile writes a new file name under root: O_EXCL fails on anything
// already there, a symlink or FIFO included (E_SPECIAL_FILE), and never
// follows or blocks on it.
func createFile(root *os.Root, name string, data []byte) error {
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		if fi, lerr := root.Lstat(name); lerr == nil && !fi.Mode().IsRegular() {
			return errf("E_SPECIAL_FILE", "%s is not a regular file", name)
		}
		return errf("E_OUTPUT", "%v", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close() //nolint:errcheck,gosec // the write error wins
		return errf("E_OUTPUT", "%v", err)
	}
	if err := f.Close(); err != nil {
		return errf("E_OUTPUT", "%v", err)
	}
	return nil
}
