package evidence

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func compileSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	sch, err := jsonschema.NewCompiler().Compile(filepath.Join("..", "..", "schema", "evidence-record-1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	return sch
}

func validateLine(sch *jsonschema.Schema, line []byte) error {
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(line))
	if err != nil {
		return err
	}
	return sch.Validate(v)
}

// Every complete line the writer produced validates against the schema.
func TestSchemaAcceptsGoldens(t *testing.T) {
	sch := compileSchema(t)
	for _, f := range []string{"chain-good.jsonl", "chain-break.jsonl", "chain-segment.jsonl", "chain-truncated.jsonl"} {
		b := readFile(t, filepath.Join("testdata", f))
		lines := bytes.Split(b, []byte("\n"))
		for i, l := range lines[:len(lines)-1] { // the last element is empty or the cut line
			if err := validateLine(sch, l); err != nil {
				t.Errorf("%s line %d: %v", f, i+1, err)
			}
		}
	}
}

// Writer-side validation accepts every golden record the schema accepts.
func TestValidateGoldens(t *testing.T) {
	for i, l := range goodLines(t) {
		var r Record
		if err := json.Unmarshal(l, &r); err != nil {
			t.Fatal(err)
		}
		if err := validate(&r); err != nil {
			t.Errorf("line %d: %v", i+1, err)
		}
	}
}

// The schema rejects what the writer refuses, so ctfkit gets the same rules.
func TestSchemaRejects(t *testing.T) {
	sch := compileSchema(t)
	evalLine := string(goodLines(t)[2])
	cases := map[string][2]string{
		"cross-kind property": {`"kind":"eval"`, `"event":"floor_reset","kind":"eval"`},
		"quoted map key path": {`"paths":["storage_encrypted"]`, `"paths":["tags[\"password\"]"]`},
		"unknown err class":   {`"decision":"logged"`, `"decision":"logged","err":"boom"`},
		"extra property":      {`"stage":"plan"`, `"stage":"plan","value":"x"`},
		"envelope not absent": {`"digests":{`, `"envelope":"present","digests":{`},
		"bad digest":          {`"verdict":null`, `"verdict":"sha256:00"`},
		"untrusted source":    {`"source":"profile"`, `"source":"env"`},
		"identity value key":  {`"identity":null`, `"identity":{"Name":"x"}`},
		"missing results":     {`,"results":[`, `,"x":[`},
		"wrong kind":          {`"kind":"eval"`, `"kind":"evaluation"`},
		"missing header":      {`"v":1`, `"w":1`},
	}
	confLine := string(goodLines(t)[1])
	confCases := map[string][2]string{
		"unknown bundle source": {`"source":"cache"`, `"source":"disk"`},
		"bundle source extra":   {`"source":"cache"}`, `"source":"cache","path":"x"}`},
		"unknown skip reason":   {`"reasons":["digest_mismatch"`, `"reasons":["bad_name"`},
		"repeated skip reason":  {`"reasons":["digest_mismatch","unverified"]`, `"reasons":["unverified","unverified"]`},
		"negative skip count":   {`"count":2`, `"count":-1`},
		"skip count over cap":   {`"count":2`, `"count":1000000000000000`},
		"skip file name":        {`"count":2`, `"count":2,"files":["sha256-x.tar.gz"]`},
	}
	run := func(name, fixture string, c [2]string) {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(fixture, c[0]) {
				t.Fatalf("fixture lacks %s", c[0])
			}
			line := strings.Replace(fixture, c[0], c[1], 1)
			if !json.Valid([]byte(line)) {
				t.Fatalf("not JSON: %s", line)
			}
			if err := validateLine(sch, []byte(line)); err == nil {
				t.Errorf("schema accepted %s", name)
			}
		})
	}
	for name, c := range cases {
		run(name, evalLine, c)
	}
	for name, c := range confCases {
		run(name, confLine, c)
	}
	if err := validateLine(sch, []byte(strings.Replace(confLine, `"count":2`, `"count":999999999999999`, 1))); err != nil {
		t.Errorf("schema rejected the count cap: %v", err)
	}
	run("bundle_sources on eval", evalLine, [2]string{`"digests":{`, `"bundle_sources":[],"digests":{`})
	// Verdict gate fields.
	matched := string(readFile(t, filepath.Join("testdata", "records", "verdict_matched.json")))
	for name, c := range map[string][2]string{
		"matched on plan":         {`"stage":"apply_pre"`, `"stage":"plan"`},
		"matched without verdict": {`"verdict":"sha256:` + strings.Repeat("e", 64) + `"`, `"verdict":null`},
		"matched entry negative":  {`"entry":0`, `"entry":-1`},
		"matched key not digest":  {`"entry":0,"instance_key":"sha256:1`, `"entry":0,"instance_key":"x1`},
		"matched address":         {`"entry":0,`, `"address":"aws_s3_bucket.a","entry":0,`},
		"unknown situation":       {`"situation":"pass"`, `"situation":"maybe"`},
	} {
		run(name, matched, c)
	}
	rpc := string(readFile(t, filepath.Join("testdata", "records", "rpc_refused.json")))
	run("rpc stage with a resource type", rpc, [2]string{`"type":"rpc_upgrade_resource_state"`, `"type":"aws_db_instance"`})
}

// The configure event enum is closed: the schema and the writer list the
// same values in the same order, and each one (with the self-service scope
// rejection and the air-gap break_glass drop) validates on a
// configure line in both.
func TestEventEnumMatchesSchema(t *testing.T) {
	var s struct {
		OneOf []struct {
			Properties map[string]struct {
				Enum []string `json:"enum"`
			} `json:"properties"`
		} `json:"oneOf"`
	}
	if err := json.Unmarshal(readFile(t, filepath.Join("..", "..", "schema", "evidence-record-1.schema.json")), &s); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, b := range s.OneOf {
		if e := b.Properties["event"].Enum; e != nil {
			if got != nil {
				t.Fatal("more than one oneOf branch lists an event enum")
			}
			got = e
		}
	}
	if !slices.Equal(got, events) {
		t.Errorf("schema events %v, writer events %v", got, events)
	}
	for _, e := range []string{"exception_self_service_scope", "break_glass_dropped"} {
		if !slices.Contains(events, e) {
			t.Errorf("event %s missing", e)
		}
	}
	sch := compileSchema(t)
	conf := string(goodLines(t)[1])
	for _, e := range events {
		line := strings.Replace(conf, `"event":"bundle_loaded"`, `"event":"`+e+`"`, 1)
		if err := validateLine(sch, []byte(line)); err != nil {
			t.Errorf("schema rejected event %s: %v", e, err)
		}
		var r Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		if r.Event != e {
			t.Fatalf("fixture lacks the bundle_loaded event: %s", line)
		}
		if err := validate(&r); err != nil {
			t.Errorf("writer rejected event %s: %v", e, err)
		}
	}
}

// The writer refuses the verdict gate fields where the schema does,
// plus the order the schema cannot express.
func TestValidateVerdictFields(t *testing.T) {
	load := func(name string) Record {
		var r Record
		if err := json.Unmarshal(readFile(t, filepath.Join("testdata", "records", name)), &r); err != nil {
			t.Fatal(err)
		}
		if err := validate(&r); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return r
	}
	k := "sha256:" + strings.Repeat("1", 64)
	for name, edit := range map[string]func(*Record){
		"matched on plan":         func(r *Record) { r.Stage = "plan" },
		"matched without verdict": func(r *Record) { r.Digests.Verdict = nil },
		"matched unsorted":        func(r *Record) { r.Matched = []Match{{Entry: 3, InstanceKey: k}, {Entry: 0, InstanceKey: k}} },
		"matched repeated":        func(r *Record) { r.Matched = []Match{{Entry: 1, InstanceKey: k}, {Entry: 1, InstanceKey: k}} },
		"matched negative":        func(r *Record) { r.Matched = []Match{{Entry: -1, InstanceKey: k}} },
		"matched key not digest":  func(r *Record) { r.Matched = []Match{{Entry: 0, InstanceKey: "aws_s3_bucket.a"}} },
		"unknown situation":       func(r *Record) { r.Results[0].Situation = "maybe" },
	} {
		r := load("verdict_matched.json")
		edit(&r)
		if err := validate(&r); err == nil {
			t.Errorf("validate accepted %s", name)
		}
	}
	r := load("rpc_refused.json")
	r.Resource.Type = "aws_db_instance"
	if err := validate(&r); err == nil {
		t.Error("validate accepted stage rpc with a resource type")
	}
	if r := load("verdict_no_match.json"); r.Matched == nil || len(r.Matched) != 0 {
		t.Errorf("empty matched decoded as %v, want an empty list", r.Matched)
	}
}
