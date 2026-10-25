package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/baseline"
	"github.com/compliancetf/terraform-provider-aws/internal/breakglass"
	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/embedded"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/celeng"
	"github.com/compliancetf/terraform-provider-aws/internal/evidence"
	"github.com/compliancetf/terraform-provider-aws/internal/exceptions"
	"github.com/compliancetf/terraform-provider-aws/internal/fetch"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
	"github.com/compliancetf/terraform-provider-aws/internal/verdict"
)

const maxBundleFile = 8 << 20 // compressed archive limit of the reader

// Options of a Lifecycle. ProviderVersion is the compiled wrapper version;
// Now defaults to time.Now.
type Options struct {
	ProviderVersion string
	ProviderAddress string // evidence provider.address
	WrapperName     string // verdict provider_versions name, compliancetf/<type>
	UpstreamName    string // manifest upstream.source and verdict provider_versions name, hashicorp/<type>
	UpstreamVersion string // evidence provider.upstream_version
	CISBundle       []byte // signed CIS archive (wrapper Config.CISBundle); nil: the compiled internal/embedded copy
	Now             func() time.Time
}

// Lifecycle is the 0B evaluator. Configure loads everything; later stages
// read the Configured snapshot.
type Lifecycle struct {
	opt      Options
	verdict  Verdict      // entry matcher
	loaded   verdict.Lazy // COMPLIANCETF_VERDICT, loaded at the first apply
	bgOnce   sync.Once    // breakglass.Verify of the loaded verdict, once
	bgSet    *breakglass.Set
	compiler engine.Compiler // nil: the Configured celeng compiler (compilerFor); tests set a fake
	// testPerResource replaces the per-resource budget when set. Only tests
	// set it, so goldens that do not test budgets cannot time out on a
	// loaded machine; production budgets come from budgetsOf alone.
	testPerResource time.Duration
	mu              sync.RWMutex
	cfg             *Configured
	// scoped caches scopedToVerdict for one Configured.
	scopeMu  sync.Mutex
	scopeFor *Configured
	scopeCfg *Configured
	scopeErr error
	progs    sync.Map // progKey -> progEntry
	// spent is compile plus evaluation time in this process, ns: the per-run
	// budget is per process by spec, never reset. A provider process
	// serves one Terraform command.
	spent atomic.Int64

	evMu     sync.Mutex
	ev       *evidence.Writer // nil until Configure opens it, or when opening failed
	evClass  string           // class of the failed open
	evWarned atomic.Bool      // a write failure warns once
}

// Configured is the outcome of a successful Configure.
type Configured struct {
	Block      Block
	Resolution profile.Resolution
	Table      profile.ModeTable
	Floor      *trust.Floor // nil when no floor was required
	Controls   *bundle.ControlSet
	Content    string                  // content digest of Controls under the bundle-declared coverable map
	Bundles    []string                // digests of the loaded bundles, sorted
	Sources    []evidence.BundleSource // source of each loaded bundle, in Bundles order
	Skipped    evidence.CacheSkipped   // bundle cache archives not used (CachedTrust scan)
	Events     []string                // configure evidence events, bundle_loaded first
	Sidecar    *exceptions.Sidecar     // nil: no self-service sidecar applies
	Grants     *exceptions.Grants      // nil: no exception_grants_dir
	Baseline   Baseline                // *baseline.Set; nil, or a nil set: no baseline file
	// Coverability is the effective signed coverable map; plan
	// reads it for provisional exemption eligibility. The zero
	// value covers nothing.
	Coverability exceptions.Coverability
	// BreakGlass is the receipt policy: the apply path passes it
	// with the loaded verdict to breakglass.Verify. The zero Policy honors
	// nothing.
	BreakGlass breakglass.Policy
	Provider   engine.ProviderInfo
	Schemas    celeng.SchemaSource // upstream schemas (0A ConfigureRequest.Schemas); nil: no control compiles
	compiler   *celeng.Compiler    // the cel engine.Compiler over Schemas
	// tableIn is the input of Table; apply recomputes the table with the
	// verdict scope (scopedToVerdict). A zero tableIn keeps Table.
	tableIn profile.TableInput
	// reset is the floor reset the floor_reset event attests; its
	// unrecorded flag is cleared once the record is written.
	reset *unrecordedReset
}

type unrecordedReset struct {
	dir, org string
	at       time.Time
}

// New returns an unconfigured Lifecycle.
func New(opt Options) *Lifecycle {
	if opt.Now == nil {
		opt.Now = time.Now
	}
	return &Lifecycle{opt: opt, verdict: noVerdict{}}
}

// Configured returns the last successful Configure outcome, nil before.
func (l *Lifecycle) Configured() *Configured {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.cfg
}

// Configure loads the compliance block, org, trust state, floor statement,
// profile, mode table and bundles, in the spec order (Floor statement,
// Order): profile candidates are verified, floor_mode comes from the highest
// candidate, the floor is validated, then every profile and bundle below it
// is rejected. compliance is the stripped compliance {} object (may be
// null) and schemas the upstream schemas the cel compiler loads controls
// against (nil: every control is not_evaluable). It returns warnings; any
// error fails Configure. A successful Configure opens the process evidence
// chain and writes the configure record. A self_service_scope rejection
// also opens a chain and writes its one configure record, drops the earlier
// snapshot and returns only the evidence warnings with its error.
func (l *Lifecycle) Configure(ctx context.Context, compliance tftypes.Value, terraformVersion string, schemas celeng.SchemaSource) ([]string, error) {
	return l.configureWith(ctx, compliance, terraformVersion, engine.ProviderInfo{}, schemas)
}

// configureWith is Configure with the provider binding of the upstream
// provider config (Hook.Configure).
func (l *Lifecycle) configureWith(ctx context.Context, compliance tftypes.Value, terraformVersion string, prov engine.ProviderInfo, schemas celeng.SchemaSource) ([]string, error) {
	c, warns, err := l.configure(ctx, compliance)
	if err != nil {
		if c == nil {
			return nil, err
		}
		// A rejection with its own configure event. The chain is
		// now the rejection's, so no earlier snapshot may evaluate into it:
		// drop it, and later stages fail closed as before any Configure.
		warns := l.openEvidence(c, terraformVersion)
		l.mu.Lock()
		l.cfg = nil
		l.progs.Clear()
		l.mu.Unlock()
		return warns, err
	}
	c.Provider, c.Schemas, c.compiler = prov, schemas, celeng.NewCompilerFor(schemas, c.Controls, c.Content)
	if c.Controls != nil {
		// Compile once here, outside every per-resource budget (5.7) and the
		// per-run spend: Evaluate only looks programs up.
		c.compiler.Precompile(c.Controls.All())
	}
	warns = append(warns, l.openEvidence(c, terraformVersion)...)
	l.mu.Lock()
	l.cfg = c
	// Programs of the snapshot before are keyed by its compiler and never
	// hit again. One storing from an evaluation still in flight
	// on that snapshot stays until the next Configure.
	l.progs.Clear()
	l.mu.Unlock()
	return warns, nil
}

func (l *Lifecycle) configure(ctx context.Context, compliance tftypes.Value) (*Configured, []string, error) {
	if err := checkBreakGlass(); err != nil {
		return nil, nil, err // before any read or fetch
	}
	b, err := parseBlock(compliance)
	if err != nil {
		return nil, nil, err
	}
	pin, err := trust.OrgPin()
	if err != nil {
		return nil, nil, err
	}
	org, err := profile.ResolveOrg(b.HCLOrg, b.EnvOrg, pin, os.Getenv("COMPLIANCETF_GOVERNED"))
	if err != nil {
		return nil, nil, err
	}
	stateDir, err := trust.StateDir()
	if err != nil {
		return nil, nil, err
	}
	state, err := trust.LoadState(stateDir)
	if err != nil {
		return nil, nil, err // unreadable state fails closed
	}
	release, err := trust.EmbeddedReleaseFloor()
	if err != nil {
		return nil, nil, err
	}
	now := l.opt.Now()
	var warns []string

	cacheDir, err := cacheDir()
	if err != nil {
		return nil, nil, err
	}
	// Local bundle candidates first: embedded CIS, the air-gap archive and
	// every verifying cached archive merge their revocations before the floor;
	// verified manifests raise the bundle and profile minimums.
	revs := state.Revocations
	local, w, err := localBundles(b, l.opt.CISBundle, now, revs)
	if err != nil {
		return nil, nil, err
	}
	warns = append(warns, w...)
	revs, cached, w, skipped, err := fetch.CachedTrust(cacheDir, revs)
	if err != nil {
		return nil, nil, err
	}
	warns = append(warns, w...)
	mins := manifestMins{org: org.ID, bundles: map[string]int64{}}
	for _, m := range cached {
		mins.add(m)
	}
	for _, lb := range local {
		if revs, err = trust.Merge(revs, lb.Revocations); err != nil {
			return nil, nil, err
		}
		mins.add(lb.Manifest)
	}

	token, offline := os.Getenv("COMPLIANCETF_TOKEN"), os.Getenv("COMPLIANCETF_OFFLINE") == "true"
	client, err := fetch.New(fetch.Config{Token: token, CacheDir: cacheDir, Offline: offline, Now: l.opt.Now})
	if err != nil {
		return nil, nil, err
	}

	var cands profile.Candidates
	var floor *trust.Floor
	floorMode, reset := "", false
	if org.ID != "" {
		src := profile.Sources{EnvPath: b.EnvProfilePath, ServiceExpected: token != "", HCLPath: b.HCLProfilePath, CacheDir: cacheDir}
		var w []string
		if src.Service, w, err = client.Profile(ctx, org.ID, revs); err != nil {
			return nil, nil, err
		}
		warns = append(warns, w...)
		cands = profile.LoadCandidates(src, org.ID, revs)
		// A floor_mode disagreement fails in obtainFloor; here it only skips.
		if mode, err := cands.FloorMode(org.Governed); err == nil && mode == trust.FloorOnline && token != "" && !offline {
			pre := trust.Floors{OrgID: org.ID, Release: release, Manifest: mins.bundles}
			if revs, w, err = prefetchRevocations(ctx, client, org.ID, cands, state, pre, revs, &mins); err != nil {
				return nil, nil, err
			}
			warns = append(warns, w...)
			cands = profile.LoadCandidates(src, org.ID, revs) // re-verify under the merged set
		}
		if floor, floorMode, state, reset, err = l.obtainFloor(ctx, org, cands, revs, state, stateDir, &warns); err != nil {
			return nil, nil, err
		}
	}

	floors := trust.Floors{OrgID: org.ID, Mode: floorMode, Release: release, Statement: floor, Manifest: mins.bundles}
	var pmin int64
	if org.ID != "" {
		if pmin, err = state.EffectiveProfileMin(floors); err != nil {
			return nil, nil, err
		}
		pmin = max(pmin, mins.profile) // a verified org manifest's min_profile_version
	}
	res, err := profile.Resolve(profile.Input{Org: org, Candidates: cands, MinVersion: pmin,
		FloorMode: floorMode, ProviderVersion: l.opt.ProviderVersion, Now: now})
	if err != nil {
		return nil, nil, err
	}
	warns = append(warns, res.Warnings...)
	warns = append(warns, phase3Warnings(res.Profile, floorMode)...)
	warns = append(warns, previewWarnings(res.Profile, verdictRequiredGA)...)
	tableIn := profile.TableInput{Resolution: res,
		HCLMode: b.HCLMode, EnvMode: b.EnvMode, HCLEnvironment: b.HCLEnvironment, EnvEnvironment: b.EnvEnvironment,
		Workspace: b.Workspace, SidecarConfigured: b.ExceptionsFile != "",
		HCLDataSources: b.HCLDataSources, EnvDataSources: b.EnvDataSources}
	table, err := profile.ComputeModeTable(tableIn)
	if err != nil {
		return nil, nil, err
	}
	warns = append(warns, table.Warnings...)
	if b.FieldsWarning != "" {
		warns = append(warns, b.FieldsWarning)
	}

	floors.Governed = res.Governed
	var profVersion int64
	var required []profile.BundleMin
	if p := res.Profile; p != nil {
		profVersion, required = p.ProfileVersion, p.Bundles
		floors.FloorRequired = len(required) > 0
		floors.Profile = map[string]int64{}
		for _, bm := range required {
			floors.Profile[bm.BundleID] = bm.MinVersion
		}
	}
	loaded, w, err := l.loadBundles(ctx, client, org.ID, local, required, profVersion, state, floors, revs)
	if err != nil {
		return nil, nil, err
	}
	warns = append(warns, w...)
	cs, w, err := bundle.NewControlSet(org.ID, now, revs, loaded...)
	if err != nil {
		return nil, nil, err
	}
	// A bundle with iam.* controls and no iam-actions.json is rejected
	// before any state records it as accepted.
	if err := celeng.CheckCatalogs(cs.All(), cs.IAMCatalog); err != nil {
		return nil, nil, err
	}
	warns = append(warns, w...)
	events := []string{"bundle_loaded"}
	// An applied reset, or one applied by an earlier run that then failed:
	// either way the mark carries the unrecorded flag.
	var unrec *unrecordedReset
	if m := state.Floors[org.ID]; org.ID != "" && (reset || m.ResetUnrecorded) {
		events = append(events, "floor_reset")
		unrec = &unrecordedReset{dir: stateDir, org: org.ID, at: m.ResetIssuedAt}
	}
	for _, rj := range res.Rejected { // named in a warning by profile.Resolve
		if rj.Rollback {
			events = append(events, "rollback_rejected")
		}
	}
	for range w { // NewControlSet warns only for bundles inside the expiry grace
		events = append(events, "bundle_expired_grace")
	}
	if org.ID != "" && res.Profile == nil {
		events = append(events, "profile_missing")
	}
	profMode := ""
	if res.Profile != nil {
		profMode = res.Profile.FloorMode
	}
	// break_glass coverability is dropped unless every mode is online.
	cov, w := exceptions.NewCoverability(cs.Coverable(), table.Exceptions, profMode, floorMode)
	warns = append(warns, w...)
	// NewCoverability warns only for a break_glass drop, so any warning is
	// one; one event per Configure, value-free: no control ids.
	if len(w) > 0 {
		events = append(events, "break_glass_dropped")
	}
	if err := table.Exceptions.CheckSelfService(func(id string) bool { return cov.Coverable(id, string(bundle.CoverSelfService)) }); err != nil {
		return nil, nil, err
	}
	warns = append(warns, exceptions.ForbidUnmatched(table, cs.ResolveFold)...)
	// under floor_mode airgap exceptions use the stored floor
	// issued_at, never the local clock.
	clock := exceptions.NewClock(state, org.ID, profMode, floorMode)
	delta := trust.State{Bundles: map[string]int64{}, Revocations: cs.Revocations()}
	var digests []string
	var sources []evidence.BundleSource
	for _, lb := range loaded {
		delta.Bundles[lb.Manifest.BundleID] = lb.Manifest.BundleVersion
		digests = append(digests, lb.Digest)
		sources = append(sources, evidence.BundleSource{Digest: lb.Digest, Source: lb.Source})
	}
	slices.Sort(digests)
	slices.SortFunc(sources, func(a, b evidence.BundleSource) int { return strings.Compare(a.Digest, b.Digest) })
	side, n, err := loadSidecar(b, table, cs, cov, now, clock)
	if errors.Is(err, exceptions.ErrSelfServiceScope) {
		// Configure fails, but the rejection is attested: configureWith
		// writes this snapshot's one configure record. Nothing
		// else is recorded; no bundle is accepted into trust state.
		return &Configured{Block: b, Resolution: res, Table: table, Controls: cs, Bundles: digests,
			Events: []string{"exception_self_service_scope"}}, nil, err
	}
	if err != nil {
		return nil, nil, err
	}
	warns, events = append(warns, n.Warnings...), append(events, n.Events...)
	// signed grants, verified against the same clock.
	var highWater int64 // 0 when no floor is required
	if floor != nil {
		highWater = state.Floors[org.ID].Epoch
	}
	grants, n, err := loadGrants(b, table, cs, cov, org.ID, now, clock, highWater)
	if err != nil {
		return nil, nil, err
	}
	for _, e := range n.Events {
		if !slices.Contains(events, e) {
			events = append(events, e)
		}
	}
	warns = append(warns, n.Warnings...)
	// the signed baseline, verified before anything is saved.
	bl, err := baseline.Load(baseline.LoadInput{Path: b.BaselineFile, KeyPath: os.Getenv(baseline.EnvKeyFile), Profile: res.Profile,
		Revocations: cs.Revocations(), Coverable: func(id string) bool { return cov.Coverable(id, string(bundle.CoverBaseline)) }, Now: now})
	if err != nil {
		return nil, nil, err
	}

	if res.Profile != nil {
		delta.Profiles = map[string]int64{org.ID: profVersion}
	}
	merged, w2, err := saveState(stateDir, delta)
	if err != nil {
		return nil, nil, err
	} else if w2 != "" {
		warns = append(warns, w2)
	}
	if err := checkMerged(merged, floors, loaded, org.ID, res.Profile); err != nil {
		return nil, nil, err
	}
	warns = append(warns, grandfatherWarning(table, bl != nil)...) // last: only a successful Configure spends the once
	return &Configured{Block: b, Resolution: res, Table: table, Floor: floor, Controls: cs, Content: cs.ContentDigest(cov.Kinds()), Bundles: digests, Sources: sources, Skipped: cacheSkipped(skipped), Events: events, Sidecar: side, Grants: grants, Baseline: bl, Coverability: cov, reset: unrec,
		BreakGlass: breakglass.Policy{Profile: res.Profile, FloorMode: floorMode, Revocations: cs.Revocations(), Coverable: func(id string) bool { return cov.Coverable(id, string(bundle.CoverBreakGlass)) }},
		tableIn:    tableIn}, warns, nil
}

// loadSidecar loads the self-service exceptions_file against the mode table;
// nil when none is configured or no control is self-service.
func loadSidecar(b Block, t profile.ModeTable, cs *bundle.ControlSet, cov exceptions.Coverability, now time.Time, clock exceptions.Clock) (*exceptions.Sidecar, exceptions.Notices, error) {
	return exceptions.LoadSidecar(b.ExceptionsFile, exceptions.SidecarInput{Table: t, Resolve: cs.Resolve, ResolveFold: cs.ResolveFold, Coverable: cov, Now: now, Clock: clock})
}

// loadGrants verifies the signed grants of exception_grants_dir (nil when
// none is configured) with the compiled keyring plus the profile grant_keys,
// the merged revocations and the run's exceptions clock, so under airgap no
// grant time check reads the process clock. A bad grant key set
// is a configuration error. Grants bind the loaded content digest, the floor
// epoch high-water and the merged control revocations.
func loadGrants(b Block, t profile.ModeTable, cs *bundle.ControlSet, cov exceptions.Coverability, orgID string, now time.Time, clock exceptions.Clock, floorEpoch int64) (*exceptions.Grants, exceptions.Notices, error) {
	if b.GrantsDir == "" {
		return nil, exceptions.Notices{}, nil
	}
	compiled, err := trust.Embedded()
	if err != nil {
		return nil, exceptions.Notices{}, err
	}
	v, err := exceptions.NewVerifier(exceptions.VerifierInput{Compiled: compiled, Revocations: cs.Revocations(),
		Table: t, OrgID: orgID, Now: now, Clock: clock})
	if err != nil {
		return nil, exceptions.Notices{}, err
	}
	return exceptions.LoadGrants(exceptions.GrantsInput{Dir: b.GrantsDir, Verifier: v, Coverable: cov, Resolve: cs.Resolve, ResolveFold: cs.ResolveFold, Table: t,
		ContentDigest: cs.ContentDigest(cov.Kinds()), FloorEpoch: floorEpoch, Revoked: cs.ControlRevoked})
}

// obtainFloor validates the floor statement when a candidate or the org needs
// one, in the floor_mode of the highest candidate (never inferred), and
// persists its high-water at once. A non-governed org whose candidates list
// no bundles skips the floor. A
// floor reset artifact is applied first; reset reports that one was
// applied (event floor_reset). It returns the trust state merged with the
// reset and the floor delta.
func (l *Lifecycle) obtainFloor(ctx context.Context, org profile.Org, cands profile.Candidates, revs trust.Revocations,
	state trust.State, stateDir string, warns *[]string) (f *trust.Floor, mode string, merged trust.State, reset bool, err error) {
	need, airgapPath, err := cands.FloorNeeds()
	if err != nil {
		return nil, "", state, false, err
	}
	mode, err = cands.FloorMode(org.Governed)
	if err != nil {
		return nil, "", state, false, err
	}
	switch {
	case !need && !org.Governed:
		return nil, "", state, false, nil
	case mode == "": // profile parse requires floor_mode here; fail closed anyway
		return nil, "", state, false, fmt.Errorf("Org floor for %s unavailable: governed runs need a signed floor statement (floor_mode unknown).", org.ID) //nolint:staticcheck // spec text
	}
	fc, err := fetch.NewFloorClient(fetch.FloorConfig{Token: os.Getenv("COMPLIANCETF_TOKEN"),
		Offline: os.Getenv("COMPLIANCETF_OFFLINE") == "true", EnvPath: os.Getenv("COMPLIANCETF_FLOOR_PATH")})
	if err != nil {
		return nil, "", state, false, err
	}
	// A reset is persisted before the floor statement is checked; if
	// Configure fails after it, no configure record carries floor_reset yet:
	// the error says it was applied and the mark keeps its
	// unrecorded flag for the next successful Configure.
	applied := false
	defer func() {
		if applied && err != nil {
			err = fmt.Errorf("%w (a floor reset for %s was applied before this failure; the next successful Configure records it)", err, org.ID)
		}
	}()
	in := trust.FloorInput{OrgID: org.ID, Mode: mode, ProviderVersion: l.opt.ProviderVersion, Now: l.opt.Now(), Revs: revs, State: state}
	// The reset sees the merged revocations of state and every loaded bundle.
	// Ignored or not persisted: warn and continue with the returned state.
	// Pending or an unreadable state: fail closed, state unchanged.
	s, applied, err := trust.ApplyFloorReset(stateDir, in)
	switch {
	case errors.Is(err, trust.ErrFloorResetIgnored), errors.Is(err, trust.ErrStateNotSaved):
		*warns = append(*warns, fmt.Sprintf("Floor reset not applied: %v.", err))
	case err != nil:
		return nil, "", state, false, err
	}
	in.State = s
	f, delta, err := fc.Floor(ctx, in, airgapPath)
	if errors.Is(err, trust.ErrFloorRevocationPending) {
		// Keep the pending high-water so an older floor stays refused, then
		// fail closed.
		if _, _, serr := saveState(stateDir, delta); serr != nil {
			return nil, "", s, false, errors.Join(err, serr)
		}
		return nil, "", s, false, err
	}
	if err != nil {
		return nil, "", s, false, err
	}
	merged, w, err := saveState(stateDir, delta)
	if err != nil {
		return nil, "", s, false, err
	}
	if w != "" {
		*warns = append(*warns, w)
	}
	return f, mode, merged, applied, nil
}

// prefetchRevocations fetches, before the floor, every bundle a verified
// candidate lists at the pre-floor minimum, only to merge its revocations:
// a floor whose revocation epoch only the
// service carries would otherwise never clear. The controls and minimums of
// these bundles are not used here (their min_bundle_version raises mins);
// loadBundles fetches and checks them again after the floor. A failed fetch
// is a warning: the floor fails closed on its own if it needed that bundle.
func prefetchRevocations(ctx context.Context, client *fetch.Client, org string, cands profile.Candidates,
	state trust.State, pre trust.Floors, revs trust.Revocations, mins *manifestMins) (trust.Revocations, []string, error) {
	ids, top := cands.Bundles()
	var warns []string
	for _, id := range ids {
		min, err := state.EffectiveBundleMin(id, pre)
		if err != nil {
			return revs, nil, err
		}
		b, w, err := client.Bundle(ctx, org, id, min, top, revs)
		if err != nil {
			// A verified but rejected manifest still raises the minimums
			// (mins.add keeps only this org or public), so a profile below its
			// min_profile_version cannot be selected.
			if re := (*fetch.RejectedError)(nil); errors.As(err, &re) {
				mins.add(re.Manifest)
			}
			warns = append(warns, fmt.Sprintf("Bundle %s not prefetched before the floor: %v.", id, err))
			continue
		}
		warns = append(warns, w...)
		if revs, err = trust.Merge(revs, b.Revocations); err != nil {
			return revs, nil, err
		}
		mins.add(b.Manifest)
	}
	return revs, warns, nil
}

// manifestMins are the minimums of verified manifests for this org or
// public: min_bundle_version per bundle_id and min_profile_version (public
// bundles carry 0). Both only raise the effective minimums.
type manifestMins struct {
	org     string
	bundles map[string]int64
	profile int64
}

func (mm *manifestMins) add(m *bundle.Manifest) {
	if m.OrgID != "" && m.OrgID != mm.org {
		return
	}
	mm.bundles[m.BundleID] = max(mm.bundles[m.BundleID], m.MinBundleVersion)
	mm.profile = max(mm.profile, m.MinProfileVersion)
}

// localBundles reads the embedded CIS bundle and the air-gap archive
// (control_bundle_path). They are verified here; minimums and org are
// checked by loadBundles and NewControlSet.
func localBundles(b Block, cisArchive []byte, now time.Time, revs trust.Revocations) ([]*bundle.Bundle, []string, error) {
	var warns []string
	if cisArchive == nil {
		cisArchive = embedded.Archive()
	}
	cis, w, err := embedded.CISFrom(cisArchive, now, revs)
	if err != nil {
		return nil, nil, err
	}
	if w != "" {
		warns = append(warns, w)
	}
	out := []*bundle.Bundle{cis}
	if b.BundlePath == "" {
		return out, warns, nil
	}
	raw, err := readFile(b.BundlePath, maxBundleFile)
	if err != nil {
		return nil, nil, fmt.Errorf("control_bundle_path: %w", err)
	}
	ab, err := bundle.ReadArchive(raw, func(env []byte, pt string) (trust.Verified, error) { return trust.Verify(env, pt, revs) })
	if err != nil {
		return nil, nil, fmt.Errorf("control_bundle_path %s: %w", b.BundlePath, err)
	}
	ab.Source = bundle.SourceLocal
	return append(out, ab), warns, nil
}

// cacheSkipped is the evidence form of the skip reasons: the count and the
// distinct reasons, sorted.
func cacheSkipped(reasons []string) evidence.CacheSkipped {
	distinct := slices.Compact(slices.Sorted(slices.Values(reasons)))
	if distinct == nil {
		distinct = []string{} // reasons is never null
	}
	return evidence.CacheSkipped{Count: int64(len(reasons)), Reasons: distinct}
}

// loadBundles applies the effective minimums to the local bundles and loads
// every bundle the profile requires: from the air-gap archive when it carries
// that bundle_id, else through the fetch client (service, then cache). An
// embedded bundle below its minimum that the profile requires is replaced by
// the fetched copy. Every loaded manifest must admit the provider version.
func (l *Lifecycle) loadBundles(ctx context.Context, client *fetch.Client, org string, local []*bundle.Bundle,
	required []profile.BundleMin, profVersion int64, state trust.State, floors trust.Floors, revs trust.Revocations) ([]*bundle.Bundle, []string, error) {
	var warns []string
	var out []*bundle.Bundle
	have := map[string]bool{}
	for _, lb := range local {
		m := lb.Manifest
		min, err := state.EffectiveBundleMin(m.BundleID, floors)
		if err != nil {
			return nil, nil, err
		}
		wanted := slices.ContainsFunc(required, func(r profile.BundleMin) bool { return r.BundleID == m.BundleID })
		switch {
		case m.BundleVersion < min && lb.Embedded && wanted:
			continue // the profile-required copy is fetched below
		case m.BundleVersion < min && lb.Embedded:
			return nil, nil, fmt.Errorf("embedded %s v%d is below the minimum v%d: upgrade the provider", m.BundleID, m.BundleVersion, min)
		case m.BundleVersion < min:
			return nil, nil, fmt.Errorf("control_bundle_path: bundle %s v%d is below the minimum v%d", m.BundleID, m.BundleVersion, min)
		case m.MinProfileVersion > profVersion:
			return nil, nil, fmt.Errorf("bundle %s v%d needs org profile v%d or later, run has v%d", m.BundleID, m.BundleVersion, m.MinProfileVersion, profVersion)
		}
		have[m.BundleID] = true
		out = append(out, lb)
	}
	for _, rb := range required {
		if have[rb.BundleID] {
			continue
		}
		min, err := state.EffectiveBundleMin(rb.BundleID, floors)
		if err != nil {
			return nil, nil, err
		}
		fb, w, err := client.Bundle(ctx, org, rb.BundleID, min, profVersion, revs)
		if err != nil {
			return nil, nil, err
		}
		warns = append(warns, w...)
		have[rb.BundleID] = true
		out = append(out, fb)
	}
	for _, b := range out {
		// The range is signed manifest text: name the bundle, never print it.
		if !inRange(l.opt.ProviderVersion, b.Manifest.Provider.VersionRange) {
			return nil, nil, fmt.Errorf("provider %s is outside the provider version range of bundle %s", l.opt.ProviderVersion, b.Manifest.BundleID)
		}
	}
	return out, append(warns, upstreamWarnings(l.opt.UpstreamName, l.opt.UpstreamVersion, out)...), nil
}

// upstreamWarnings warns (spec: upstream mismatch -> warning, never a load
// error) for each bundle whose signed upstream range does not admit the
// running upstream src (the manifest upstream.source this wrapper wraps)
// version u. Warnings name the bundle and the versions, never the range text.
// An unknown u is one warning: no range was checked.
func upstreamWarnings(src, u string, loaded []*bundle.Bundle) []string {
	if strings.TrimSpace(u) == "" {
		return []string{"upstream " + src + " version is unknown: bundle upstream version ranges were not checked"}
	}
	var warns []string
	for _, b := range loaded {
		up := b.Manifest.Upstream
		// No dev leniency: the upstream is a pinned release (P0A pins).
		if up.Source != src || !isRelease(u) || !meets(u, up.VersionRange, false) {
			warns = append(warns, fmt.Sprintf("upstream %s %s is outside the upstream version range of bundle %s v%d", src, u, b.Manifest.BundleID, b.Manifest.BundleVersion))
		}
	}
	return warns
}

// isRelease reports whether v is a non-empty release semantic version (no
// prerelease, not a dev build string).
func isRelease(v string) bool {
	return strings.TrimSpace(v) != "" && trust.CheckWrapper(v, v) == nil && !strings.Contains(v, "-")
}

// parityRe matches the parity prerelease wrapper versions; group 1 is
// X.Y.Z with its optional v.
var parityRe = regexp.MustCompile(`^(v?(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))-(?:beta|compliancetf)\.(?:0|[1-9][0-9]*)$`)

// inRange reports whether version v meets every comma-separated ">= x" or
// "< y" constraint of r. Any other operator, or a v that is not a semantic
// version, fails (closed). shortcut: the two operators bundles use today; add
// more when a manifest needs them.
func inRange(v, r string) bool {
	// No version is unknown, not a dev build: it fails any range on any
	// build (an empty v passes CheckWrapper(v, v) and is below every "<").
	if strings.TrimSpace(v) == "" {
		return false
	}
	// A parity beta (X.Y.Z-beta.N) or proxy-only fix (X.Y.Z-compliancetf.N)
	// wraps upstream X.Y.Z: it meets the range X.Y.Z meets, though semver
	// orders it below X.Y.Z.
	if m := parityRe.FindStringSubmatch(v); m != nil {
		v = m[1]
	}
	// Any other non-release version: a 3.0.0-rc1 is 3.x code. A dev build
	// (ctftest) meets any well-formed range; a release build never.
	dev := !isRelease(v)
	if dev && !devVersions {
		return false
	}
	return meets(v, r, dev)
}

// meets reports whether v meets every comma-separated ">= x" or "< y"
// constraint of r; a dev v meets any well-formed bound.
func meets(v, r string, dev bool) bool {
	for _, c := range strings.Split(r, ",") {
		op, ver, _ := strings.Cut(strings.TrimSpace(c), " ")
		ver = strings.TrimSpace(ver)
		// Bounds must be release versions: CheckWrapper does not order
		// prereleases, and an empty bound would pass any minimum.
		if ver == "" || trust.CheckWrapper(ver, ver) != nil || strings.Contains(ver, "-") {
			return false
		}
		below := trust.CheckWrapper(v, ver) != nil
		switch {
		case dev && (op == ">=" || op == "<"): // dev build: a valid bound is met
		case op == ">=" && !below, op == "<" && below:
		default:
			return false
		}
	}
	return true
}

// checkMerged re-checks the loaded bundles and the selected profile against
// the merged state of the final save: a concurrent run may have accepted a
// newer version after this run read the state. Below it fails
// closed.
func checkMerged(s trust.State, floors trust.Floors, loaded []*bundle.Bundle, org string, p *profile.Profile) error {
	for _, b := range loaded {
		m := b.Manifest
		min, err := s.EffectiveBundleMin(m.BundleID, floors)
		if err != nil {
			return err
		}
		if m.BundleVersion < min {
			return fmt.Errorf("bundle %s v%d is below the minimum v%d accepted by a concurrent run: rerun", m.BundleID, m.BundleVersion, min)
		}
	}
	if org == "" || p == nil {
		return nil
	}
	min, err := s.EffectiveProfileMin(floors)
	if err != nil {
		return err
	}
	if p.ProfileVersion < min {
		return fmt.Errorf("org profile v%d is below the minimum v%d accepted by a concurrent run: rerun", p.ProfileVersion, min)
	}
	return nil
}

// saveState merges delta into the trust state. Not persisting is a warning
// (the merged state still holds in process); an unreadable state fails.
func saveState(dir string, delta trust.State) (trust.State, string, error) {
	s, err := trust.UpdateState(dir, delta)
	switch {
	case err == nil:
		return s, "", nil
	case errors.Is(err, trust.ErrStateNotSaved):
		return s, fmt.Sprintf("Trust state not saved: %v.", err), nil
	}
	return trust.State{}, "", err
}

// cacheDir is COMPLIANCETF_CACHE_DIR, else os.UserCacheDir()/compliancetf;
// the profile loader and the fetch client share it.
func cacheDir() (string, error) {
	if d := os.Getenv("COMPLIANCETF_CACHE_DIR"); d != "" {
		return d, nil
	}
	d, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("cache dir: %w", err)
	}
	return filepath.Join(d, "compliancetf"), nil
}

func readFile(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // operator-named path; the archive signature is the trust boundary
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only
	b, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("file larger than %d bytes", maxBytes)
	}
	return b, nil
}
