package bundlegen

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
)

// Ledger generation_status values.
const (
	statusGenerated        = "generated"
	statusPendingReview    = "pending_review"
	statusPendingAuthoring = "pending_authoring"
	statusNotApplicable    = "not_applicable"
)

// dispositionOrder fixes the order of disposition classes in coverage.md.
var dispositionOrder = []string{"provider-local", "companion-local", "graph", "runtime", "not-expressible"}

// iacToolKeys are the catalog tool export keys of IaC scanners; a control with
// an id under one of them counts as "with an IaC tool id".
var iacToolKeys = []string{"CKV", "KICS", "TRIVY"}

// coverageReport is coverage.json.
type coverageReport struct {
	CatalogSnapshotID string                    `json:"catalog_snapshot_id"`
	Bundles           map[string]bundleCoverage `json:"bundles"`
}

// bundleCoverage counts the catalog ids a bundle selector selects. Release is
// "ga" only when every provider-local and companion-local id of the bundle
// is generated (ship gate), else "preview". NotVisible lists, per target
// resource type, the graph and runtime ids the provider cannot see;
// NotVisibleUntargeted the runtime ids without a target.
type bundleCoverage struct {
	Frameworks           []string                       `json:"frameworks"`
	Release              string                         `json:"release"`
	Controls             int                            `json:"controls"`
	Dispositions         map[string]int                 `json:"dispositions"`
	Generated            int                            `json:"generated"`
	PendingReview        []string                       `json:"pending_review"`
	PendingAuthoring     []string                       `json:"pending_authoring"`
	WithIaCToolID        int                            `json:"with_iac_tool_id"`
	Clauses              map[string]clauseCoverage      `json:"clauses"`
	NotVisible           map[string]map[string][]string `json:"not_visible"`
	NotVisibleUntargeted []string                       `json:"not_visible_untargeted"`
}

type clauseCoverage struct {
	Covered int `json:"covered"`
	Total   int `json:"total"`
}

// generationStatus is an id's ledger generation_status; generated means the
// id has a control in the emitted controls.json.
func generationStatus(d Disposition, generated bool) string {
	switch {
	case !isLocal(d.Disposition):
		return statusNotApplicable
	case generated:
		return statusGenerated
	case d.Content == "intents":
		return statusPendingReview // untranslated or a translation review item
	default:
		return statusPendingAuthoring
	}
}

// generatedIDs returns the ids of disp with a control in an emitted
// controls.json for every disposition target; an id with some targets
// uncovered (a one-type content intent on a multi-target disposition) is not
// generated. A bundle that was not emitted (nil data) has none. Generated
// status is read from the emitted bytes only, like every other property of
// a shipped control.
func generatedIDs(data []byte, disp map[string]Disposition) (map[string]bool, error) {
	ids := map[string]bool{}
	if data == nil {
		return ids, nil
	}
	cs, err := bundle.ParseControls(data)
	if err != nil {
		return nil, errf("E_EMIT", "coverage: %v", err)
	}
	have := map[string][]Target{}
	for _, c := range cs {
		have[c.ID] = append(have[c.ID], Target{Kind: string(c.Kind), Type: c.ResourceType})
	}
	for id, ts := range have {
		// only true entries: callers range over the keys (clause coverage)
		if !slices.ContainsFunc(disp[id].Targets, func(t Target) bool { return !slices.Contains(ts, t) }) {
			ids[id] = true
		}
	}
	return ids, nil
}

// Coverage builds coverage.json and coverage.md from validated inputs (the
// disposition and catalog control id sets are equal, E_DISPOSITION_COVERAGE)
// and the emitted bundle files. Every selector is reported, an empty bundle too, so
// the gap of a bundle with no generated control stays visible.
func Coverage(in Inputs, files map[string][]byte) (jsonData, md []byte, err error) {
	rep := coverageReport{CatalogSnapshotID: in.Catalog.Manifest.SnapshotID, Bundles: map[string]bundleCoverage{}}
	ids := slices.Sorted(maps.Keys(in.Catalog.Dispositions.Controls))
	for _, s := range selectors {
		gen, err := generatedIDs(files[s.id+"/controls.json"], in.Catalog.Dispositions.Controls)
		if err != nil {
			return nil, nil, err
		}
		b := bundleCoverage{
			Frameworks:           append([]string{}, s.frameworks...),
			Dispositions:         map[string]int{},
			PendingReview:        []string{},
			PendingAuthoring:     []string{},
			Clauses:              map[string]clauseCoverage{},
			NotVisible:           map[string]map[string][]string{},
			NotVisibleUntargeted: []string{},
		}
		for _, d := range dispositionOrder {
			b.Dispositions[d] = 0
		}
		for _, id := range ids {
			c := in.Catalog.Controls[id]
			if !selects(s.frameworks, c.Metadata.Frameworks) {
				continue
			}
			d := in.Catalog.Dispositions.Controls[id]
			b.Controls++
			b.Dispositions[d.Disposition]++
			if slices.ContainsFunc(iacToolKeys, func(k string) bool { return len(c.Tools[k]) > 0 }) {
				b.WithIaCToolID++
			}
			switch generationStatus(d, gen[id]) {
			case statusGenerated:
				b.Generated++
			case statusPendingReview:
				b.PendingReview = append(b.PendingReview, id)
			case statusPendingAuthoring:
				b.PendingAuthoring = append(b.PendingAuthoring, id)
			}
			if d.Disposition != "graph" && d.Disposition != "runtime" {
				continue
			}
			// validate requires targets for graph, so only runtime ids land here.
			if len(d.Targets) == 0 {
				b.NotVisibleUntargeted = append(b.NotVisibleUntargeted, id)
			}
			for _, t := range d.Targets {
				if b.NotVisible[t.Type] == nil {
					b.NotVisible[t.Type] = map[string][]string{}
				}
				// ids ascend, so a repeated id (two kinds, one type) is the last one.
				if l := b.NotVisible[t.Type][d.Disposition]; len(l) == 0 || l[len(l)-1] != id {
					b.NotVisible[t.Type][d.Disposition] = append(l, id)
				}
			}
		}
		for _, fw := range s.frameworks {
			meta, ok := in.Catalog.Frameworks[fw]
			if !ok {
				return nil, nil, errf("E_INPUT", "bundle %s: framework %s is not in frameworks_metadata.json", s.id, fw)
			}
			cc := clauseCoverage{Total: len(meta.ClauseTitles)}
			for title := range meta.ClauseTitles {
				for id := range gen {
					if slices.Contains(in.Catalog.Controls[id].Metadata.ClauseTitles[fw], title) {
						cc.Covered++
						break
					}
				}
			}
			b.Clauses[fw] = cc
		}
		b.Release = "preview"
		if b.Generated > 0 && len(b.PendingReview)+len(b.PendingAuthoring) == 0 {
			b.Release = "ga"
		}
		rep.Bundles[s.id] = b
	}
	if jsonData, err = canonicalJSON(rep); err != nil {
		return nil, nil, err
	}
	return jsonData, renderCoverage(rep), nil
}

// renderCoverage renders coverage.md from the report, bundles in selector
// order.
func renderCoverage(rep coverageReport) []byte {
	var w strings.Builder
	fmt.Fprintf(&w, "# Coverage\n\ncatalog snapshot `%s`.\n\n", rep.CatalogSnapshotID)
	w.WriteString("| Bundle | Release | Controls | Generated | Pending review | Pending authoring | With IaC tool id |\n|---|---|---|---|---|---|---|\n")
	for _, s := range selectors {
		b := rep.Bundles[s.id]
		fmt.Fprintf(&w, "| %s | %s | %d | %d | %d | %d | %d |\n", s.id, b.Release, b.Controls, b.Generated,
			len(b.PendingReview), len(b.PendingAuthoring), b.WithIaCToolID)
	}
	for _, s := range selectors {
		b := rep.Bundles[s.id]
		fmt.Fprintf(&w, "\n## %s\n\nDispositions:", s.id)
		for i, d := range dispositionOrder {
			sep := ","
			if i == 0 {
				sep = ""
			}
			fmt.Fprintf(&w, "%s %s %d", sep, d, b.Dispositions[d])
		}
		w.WriteString(".\n")
		for _, fw := range b.Frameworks {
			fmt.Fprintf(&w, "\nClauses covered in %s: %d of %d.\n", fw, b.Clauses[fw].Covered, b.Clauses[fw].Total)
		}
		if n := len(b.PendingReview) + len(b.PendingAuthoring); n > 0 {
			fmt.Fprintf(&w, "\nNot generated yet (%d):\n\n", n)
			for _, id := range b.PendingReview {
				fmt.Fprintf(&w, "- `%s`: pending review\n", id)
			}
			for _, id := range b.PendingAuthoring {
				fmt.Fprintf(&w, "- `%s`: pending authoring\n", id)
			}
		}
		if len(b.NotVisible)+len(b.NotVisibleUntargeted) > 0 {
			w.WriteString("\nNot visible to the provider:\n\n| Resource type | Disposition | Controls |\n|---|---|---|\n")
			for _, typ := range slices.Sorted(maps.Keys(b.NotVisible)) {
				for _, d := range slices.Sorted(maps.Keys(b.NotVisible[typ])) {
					fmt.Fprintf(&w, "| %s | %s | %s |\n", typ, d, strings.Join(b.NotVisible[typ][d], ", "))
				}
			}
			if len(b.NotVisibleUntargeted) > 0 {
				fmt.Fprintf(&w, "| (no resource type) | runtime | %s |\n", strings.Join(b.NotVisibleUntargeted, ", "))
			}
		}
	}
	return []byte(w.String())
}

// UpdateLedger sets generation_status on every row of the disposition
// ledger (a JSON array of rows, each with an id) from the emitted "all"
// bundle, and returns it canonically encoded. The other columns are the catalog's
// and are kept as they are. A row for an unknown id, a duplicate row or a
// missing id fails (E_LEDGER): the status cannot be written for it.
func UpdateLedger(in Inputs, files map[string][]byte, ledger []byte) ([]byte, error) {
	var rows []map[string]json.RawMessage
	if err := decodeJSON("ledger", ledger, &rows); err != nil {
		if e := (*Error)(nil); errors.As(err, &e) {
			return nil, &Error{Code: "E_LEDGER", Msg: e.Msg}
		}
		return nil, err
	}
	gen, err := generatedIDs(files["all/controls.json"], in.Catalog.Dispositions.Controls)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for i, r := range rows {
		var id string
		if err := json.Unmarshal(r["id"], &id); err != nil || id == "" {
			return nil, errf("E_LEDGER", "row %d has no id", i)
		}
		d, ok := in.Catalog.Dispositions.Controls[id]
		switch {
		case !ok:
			return nil, errf("E_LEDGER", "row %d: %s has no provider disposition", i, id)
		case seen[id]:
			return nil, errf("E_LEDGER", "row %d: duplicate id %s", i, id)
		}
		seen[id] = true
		// statuses are plain ASCII words, so the Go quoting is the JSON string.
		r["generation_status"] = json.RawMessage(strconv.Quote(generationStatus(d, gen[id])))
	}
	var missing []string
	for id := range in.Catalog.Dispositions.Controls {
		if !seen[id] {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		return nil, errf("E_LEDGER", "%d ids without a ledger row: [%s]", len(missing), strings.Join(missing, ", "))
	}
	return canonicalJSON(rows)
}

// WriteLedger rewrites the ledger file at path with UpdateLedger. The file
// must be a regular file (E_SPECIAL_FILE otherwise). The new bytes go to a
// temp file in the same directory that is renamed over path, keeping the
// mode: an interrupted write leaves the old ledger, and a symlink swapped in
// after the check is replaced, never followed.
func WriteLedger(in Inputs, out *Output, path string) (err error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return errf("E_INPUT", "%v", err)
	}
	data, err := readRegular(path)
	if err != nil {
		return err
	}
	if data, err = UpdateLedger(in, out.Files, data); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".ledger-*")
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if err != nil {
			if !closed {
				err = errors.Join(err, f.Close())
			}
			err = errors.Join(err, os.Remove(f.Name()))
		}
	}()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Chmod(fi.Mode().Perm()); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	closed = true
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
