#!/usr/bin/env bash
#
# Proto drift check. Compares the vendored tfplugin5/6 protos with
# the protocol the ecosystem speaks today and fails until every new method is
# classified in internal/tfplugin/classes.json (in the pin-bump PR, together
# with `make proto`; genroutes rejects classes for methods the pin lacks).
#
# Usage:
#   scripts/proto-drift.sh                 integrity + live check of 4 sources
#   scripts/proto-drift.sh --integrity     vendored protos match SOURCES.json
#   scripts/proto-drift.sh --self-test     offline fixture cases (testdata/drift)
#   scripts/proto-drift.sh --vendored DIR --classes FILE --source DIR
#
# Live sources, resolved through proxy.golang.org (sum.golang.org verified):
#   plugin-go  github.com/hashicorp/terraform-plugin-go@latest     (strict)
#   terraform  github.com/hashicorp/terraform@latest               (strict)
#   opentofu   github.com/opentofu/opentofu@latest, highest tfpluginN.M.proto (tofu)
#   aws-pin    terraform-plugin-go required by hashicorp/terraform-provider-aws
#              at the pinned version (lag); its go.mod comes from
#              raw.githubusercontent.com and is not sumdb-verified, only the
#              extracted version string goes on, through the verified proxy.
# Downloaded files are data: buf parses them, nothing from them is executed.
#
# Findings, keyed by full method, <message>#<field number>, <enum>#<number>.
# Values are wire shape only (streaming; field label, type, oneof membership),
# so renames of fields, messages and request types are not drift.
#   DRIFT        shared key changed, or (strict) a vendored method, or a
#                field of a message the source still has, is missing      exit 1
#   UNCLASSIFIED new method absent from classes.json                     exit 1
#   REVIEW       new field/enum value reachable from an intercepted
#                method's request/response                                exit 1
#   NOTICE       other additions; BEHIND vendored key missing (lag/tofu) exit 0
#   OpenTofu (tofu) reports UNCLASSIFIED/REVIEW as warnings, exit 0.
# A field or method whose referenced type was renamed is drift only when the
# new type lost or changed one of the old type's own keys (rebinding).
# internal/tfplugin/proto/drift-accepted.txt lists reviewed live findings
# ("<source> tfplugin<N> <VERDICT> <key>", exact lines) reported as notices.
# Exit 0 clean, 1 findings, 2 fetch or tool failure (never reported as drift).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TFPLUGIN="${ROOT}/internal/tfplugin"
TOOLS="${TFPLUGIN}/tools"
FIXTURES="${TFPLUGIN}/testdata/drift"
SEMVER='^v[0-9]+\.[0-9]+\.[0-9]+$'
# Reviewed findings the live check reports as notices; set only for live.
ACCEPTED=""
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

die2() { echo "proto-drift: $*" >&2; exit 2; }

report() { # report <level> <text>; level is error|warning|notice
	echo "$2"
	if [[ -n "${GITHUB_ACTIONS:-}" ]]; then echo "::$1 title=proto-drift::$2"; fi
	if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then echo "- $2" >> "${GITHUB_STEP_SUMMARY}"; fi
}

# normalize <proto file> <out json>: keyed shape {items, edges} of one proto.
normalize() {
	local dir
	dir="$(mktemp -d "${WORK}/buf.XXXXXX")"
	cp "$1" "${dir}/" || die2 "cannot stage $1"
	go -C "${TOOLS}" tool buf build "${dir}" --exclude-imports --exclude-source-info -o "${dir}/fds.json" \
		|| die2 "buf build failed for $1"
	# items: key -> wire value; types: key -> referenced type names (field
	# target, method input/output); shapes: declared message/enum -> its own
	# "#number" -> wire value, used to tell a rename from a rebinding.
	jq -c '
		def enumv($p): ($p + "." + .name) as $fq
			| {d: $fq}, ((.value // [])[] | {k: "E \($fq)#\(.number)", o: $fq, n: .number, v: "-"});
		def msg($p): ($p + "." + .name) as $fq | (.oneofDecl // []) as $oo
			| {d: $fq},
			  ((.field // [])[]
				| {k: "F \($fq)#\(.number)", o: $fq, n: .number,
				   v: "\(.label) \(.type) \(if .proto3Optional then "optional" elif .oneofIndex == null then "-" else "oneof:" + $oo[.oneofIndex].name end)",
				   t: (if .typeName then [.typeName] else null end)}),
			  ((.enumType // [])[] | enumv($fq)),
			  ((.nestedType // [])[] | msg($fq));
		[.file[] | .package as $pkg | ("." + $pkg) as $p
			| ((.messageType // [])[] | msg($p)),
			  ((.enumType // [])[] | enumv($p)),
			  ((.service // [])[] | .name as $s | (.method // [])[]
				| {k: "M /\($pkg).\($s)/\(.name)", m: "/\($pkg).\($s)/\(.name)", t: [.inputType, .outputType],
				   v: "client_stream=\(.clientStreaming // false) server_stream=\(.serverStreaming // false)"})]
		| {items: (map(select(.k) | {(.k): .v}) | add // {}),
		   types: (map(select(.t) | {(.k): .t}) | add // {}),
		   shapes: (reduce .[] as $x ({};
				if $x.d then .[$x.d] //= {} elif $x.o then .[$x.o]["#\($x.n)"] = $x.v else . end)),
		   edges: (map(select(.t) | (.o // .m) as $from | .t[] | [$from, .]) | group_by(.[0])
				| map({(.[0][0]): map(.[1])}) | add // {})}
	' "${dir}/fds.json" > "$2" || die2 "cannot normalize $1"
}

# compare <vendored dir> <classes.json> <source dir> <strict|lag|tofu> <label>
# Compares every tfplugin{5,6}.proto present in the source dir.
compare() {
	local vdir="$1" classes="$2" sdir="$3" mode="$4" label="$5" rc=0 v found=0 verdict text level
	for v in 5 6; do
		[[ -f "${sdir}/tfplugin${v}.proto" ]] || continue
		found=1
		normalize "${vdir}/tfplugin${v}.proto" "${WORK}/v.json"
		normalize "${sdir}/tfplugin${v}.proto" "${WORK}/s.json"
		jq -e '.items | keys | any(startswith("M "))' "${WORK}/s.json" > /dev/null \
			|| die2 "${label}: tfplugin${v}.proto declares no methods"
		jq -e '.items | keys | any(startswith("M "))' "${WORK}/v.json" > /dev/null \
			|| die2 "vendored tfplugin${v}.proto declares no methods"
		jq -r --arg mode "${mode}" --slurpfile v "${WORK}/v.json" --slurpfile s "${WORK}/s.json" '
			def reach($g; $start): {seen: {($start): true}, todo: [$start]}
				| until(.todo | length == 0; .todo[0] as $n | .todo |= .[1:]
					| reduce (($g[$n] // [])[]) as $t (.; if .seen[$t] then . else .seen[$t] = true | .todo += [$t] end))
				| .seen;
			def owner: sub("^[EF] "; "") | sub("#[0-9]+$"; "");
			. as $C | $v[0].items as $V | $s[0].items as $S
			| $v[0].types as $VT | $s[0].types as $ST | $v[0].shapes as $VS | $s[0].shapes as $SS
			# tcompat: same name, or both declared here and every own key of the
			# vendored type exists unchanged in the source type. Imported types
			# (absent from shapes) must keep their name.
			| def tcompat($a; $b): $a == $b or ($VS[$a] != null and $SS[$b] != null
				and all($VS[$a] | to_entries[]; $SS[$b][.key] == .value));
			# pairs: [vendored key, source key] for typed keys, including keys under
			# a renamed owner matched to the old owner by number.
			def pairs($r): ($VT | keys[] | select($ST[.] != null) | [., .]),
				($ST | keys[] | select($VT[.] == null) | . as $sk | ($sk | owner) as $o | ($r[$o] // [])[]
					| ("F " + . + "#" + ($sk | sub(".*#"; ""))) as $vk | select($VT[$vk] != null) | [$vk, $sk]);
			def step($r): [pairs($r) as [$vk, $sk] | range(0; $VT[$vk] | length) as $i
				| select($VT[$vk][$i] != $ST[$sk][$i] and tcompat($VT[$vk][$i]; $ST[$sk][$i]))
				| {s: $ST[$sk][$i], v: $VT[$vk][$i]}]
				| group_by(.s) | map({key: .[0].s, value: (map(.v) | unique)}) | from_entries;
			# renamed: source type -> every vendored type it replaces. step only
			# grows with $r over a finite set, so the fixed point terminates.
			({} | until(. == step(.); step(.))) as $renamed
			| [$C | to_entries[] | select(.value == "intercept") | {key, value: reach($s[0].edges; .key)}] as $reach
			| ($V | keys[] | select($S[.] != null and $S[.] != $V[.])
				| "DRIFT\t\(.): vendored [\($V[.])] source [\($S[.])]"),
			  (pairs($renamed) as [$vk, $sk]
				| select([range(0; $VT[$vk] | length)] | any(. as $i | tcompat($VT[$vk][$i]; $ST[$sk][$i]) | not))
				| "DRIFT\t\($sk): type [\($VT[$vk] | join(" "))] rebound to incompatible [\($ST[$sk] | join(" "))]"),
			  ($V | keys[] | select($S[.] == null)
				| if $mode == "strict" and (startswith("M ") or $SS[owner] != null) then "DRIFT\t\(.): removed in source"
				  else "BEHIND\t\(.): not in source" end),
			  ($S | keys[] | select($V[.] == null) | . as $k
				| select(("#" + ($k | sub(".*#"; ""))) as $n | any(($renamed[$k | owner] // [])[]; $VS[.][$n] != null) | not)
				| if startswith("M ") then
					(if $C[$k[2:]] == null then "UNCLASSIFIED\t\($k[2:]): classify it in classes.json in the pin-bump PR"
					 else "NOTICE\t\($k): new" end)
				  else ($k | owner) as $o | [$reach[] | select(.value[$o]) | .key] as $by
					| if ($by | length) > 0 then "REVIEW\t\($k): new, reachable from intercepted \($by | join(" "))"
					  else "NOTICE\t\($k): new" end
				  end)
		' "${classes}" > "${WORK}/findings.tsv" || die2 "${label}: compare failed"
		while IFS=$'\t' read -r verdict text; do
			level=notice
			case "${verdict}" in
			DRIFT) level=error ;;
			UNCLASSIFIED | REVIEW) if [[ "${mode}" == tofu ]]; then level=warning; else level=error; fi ;;
			esac
			if [[ -n "${ACCEPTED}" ]] && grep -Fxq "${label} tfplugin${v} ${verdict} ${text%%:*}" "${ACCEPTED}"; then
				level=notice; verdict="ACCEPTED ${verdict}"
			fi
			[[ "${level}" == error ]] && rc=1
			report "${level}" "${label} tfplugin${v} ${verdict} ${text}"
		done < "${WORK}/findings.tsv"
	done
	[[ "${found}" == 1 ]] || die2 "${label}: no tfplugin5.proto or tfplugin6.proto in ${sdir}"
	return "${rc}"
}

integrity() {
	local v want got rc=0
	for v in 5 6; do
		want="$(jq -r --arg f "tfplugin${v}.proto" '.[$f].sha256' "${TFPLUGIN}/proto/SOURCES.json")" || die2 "cannot read SOURCES.json"
		got="$(shasum -a 256 "${TFPLUGIN}/proto/tfplugin${v}.proto" | cut -d' ' -f1)" || die2 "cannot hash tfplugin${v}.proto"
		if [[ "${want}" != "${got}" ]]; then
			report error "integrity tfplugin${v}.proto sha256 ${got} does not match SOURCES.json ${want}; run make proto"
			rc=1
		fi
	done
	return "${rc}"
}

self_test() {
	local fail=0 c want got token
	# accepted: the unclassified fixture with its finding listed as reviewed.
	echo "accepted tfplugin5 UNCLASSIFIED /tfplugin5.Provider/GetFunctions" > "${WORK}/accepted.txt"
	for c in clean:0:NOTICE drifted:1:DRIFT unclassified:1:UNCLASSIFIED review:1:REVIEW nested:1:DRIFT accepted:0:ACCEPTED; do
		IFS=: read -r c want token <<< "${c}"
		got=0
		ACCEPTED=""; [[ "${c}" == accepted ]] && ACCEPTED="${WORK}/accepted.txt"
		compare "${FIXTURES}/base" "${FIXTURES}/base/classes.json" "${FIXTURES}/${c/accepted/unclassified}" strict "${c}" > "${WORK}/out.txt" || got=$?
		if [[ "${got}" != "${want}" ]] || ! grep -q " ${token} " "${WORK}/out.txt"; then
			echo "self-test: ${c}: exit ${got} (want ${want}), output:" >&2
			cat "${WORK}/out.txt" >&2
			fail=1
		fi
	done
	ACCEPTED=""
	[[ "${fail}" == 0 ]] && echo "self-test: ok (clean, drifted, unclassified, review, nested, accepted)"
	return "${fail}"
}

gomod() { (cd "${WORK}" && GOWORK=off GOFLAGS='' go "$@"); }

latest() {
	local ver
	ver="$(gomod list -m -json "$1@latest" | jq -r .Version)" || die2 "cannot resolve $1@latest"
	[[ "${ver}" =~ ${SEMVER} ]] || die2 "unexpected version ${ver} for $1"
	echo "${ver}"
}

moddir() {
	local dir
	dir="$(gomod mod download -json "$1@$2" | jq -r .Dir)" || die2 "cannot download $1@$2"
	[[ -d "${dir}" ]] || die2 "no module dir for $1@$2"
	echo "${dir}"
}

# stage <label> <file5> <file6>: copy a source's protos into ${WORK}/<label>.
stage() {
	mkdir -p "${WORK}/$1"
	cp "$2" "${WORK}/$1/tfplugin5.proto" || die2 "$1: missing $2"
	cp "$3" "${WORK}/$1/tfplugin6.proto" || die2 "$1: missing $3"
}

highest() { # highest <dir> <protocol>: highest-numbered tfplugin<p>.N.proto
	local n
	n="$(find "$1" -maxdepth 1 -name "tfplugin$2.*.proto" | sed -n "s|.*/tfplugin$2\.\([0-9][0-9]*\)\.proto$|\1|p" | sort -n | tail -1)"
	[[ -n "${n}" ]] || die2 "no tfplugin$2.N.proto in $1"
	echo "$1/tfplugin$2.${n}.proto"
}

live() {
	# live runs in a `||` list, where set -e is off: every $(...) that can
	# die2 in its subshell propagates exit 2 explicitly.
	local pg="github.com/hashicorp/terraform-plugin-go" ver dir aws gomodfile rc=0 src mode p5 p6
	export GOPROXY="${GOPROXY:-https://proxy.golang.org}" GOSUMDB="${GOSUMDB:-sum.golang.org}"

	ver="$(latest "${pg}")" || exit 2
	dir="$(moddir "${pg}" "${ver}")" || exit 2
	report notice "source plugin-go: ${pg}@${ver}"
	stage plugin-go "${dir}/tfprotov5/internal/tfplugin5/tfplugin5.proto" "${dir}/tfprotov6/internal/tfplugin6/tfplugin6.proto"

	ver="$(latest github.com/hashicorp/terraform)" || exit 2
	dir="$(moddir github.com/hashicorp/terraform "${ver}")" || exit 2
	report notice "source terraform: github.com/hashicorp/terraform@${ver}"
	stage terraform "${dir}/docs/plugin-protocol/tfplugin5.proto" "${dir}/docs/plugin-protocol/tfplugin6.proto"

	ver="$(latest github.com/opentofu/opentofu)" || exit 2
	dir="$(moddir github.com/opentofu/opentofu "${ver}")" || exit 2
	p5="$(highest "${dir}/docs/plugin-protocol" 5)" || exit 2
	p6="$(highest "${dir}/docs/plugin-protocol" 6)" || exit 2
	report notice "source opentofu: github.com/opentofu/opentofu@${ver}"
	stage opentofu "${p5}" "${p6}"

	aws="v$(sed -n 's/^  "version": "\(.*\)",$/\1/p' "${ROOT}/pins.json")"
	[[ "${aws}" =~ ${SEMVER} ]] || die2 "cannot read the pinned aws provider version (${aws})"
	gomodfile="${WORK}/aws.go.mod"
	curl -fsSL --max-time 30 --retry 3 -o "${gomodfile}" \
		"https://raw.githubusercontent.com/hashicorp/terraform-provider-aws/${aws}/go.mod" || die2 "cannot fetch aws ${aws} go.mod"
	if grep -Eq '^[[:space:]]*(replace[[:space:]]+)?github\.com/hashicorp/terraform-plugin-go[[:space:]].*=>' "${gomodfile}"; then
		die2 "aws ${aws} go.mod replaces terraform-plugin-go"
	fi
	ver="$(awk '$1 == "github.com/hashicorp/terraform-plugin-go" {print $2; exit}' "${gomodfile}")"
	[[ "${ver}" =~ ${SEMVER} ]] || die2 "aws ${aws} go.mod: unexpected terraform-plugin-go version '${ver}'"
	dir="$(moddir "${pg}" "${ver}")" || exit 2
	report notice "source aws-pin: hashicorp/aws ${aws} uses ${pg}@${ver}"
	stage aws-pin "${dir}/tfprotov5/internal/tfplugin5/tfplugin5.proto" "${dir}/tfprotov6/internal/tfplugin6/tfplugin6.proto"

	ACCEPTED="${TFPLUGIN}/proto/drift-accepted.txt"
	for src in plugin-go:strict terraform:strict opentofu:tofu aws-pin:lag; do
		mode="${src#*:}"; src="${src%%:*}"
		compare "${TFPLUGIN}/proto" "${TFPLUGIN}/classes.json" "${WORK}/${src}" "${mode}" "${src}" || rc=1
	done
	return "${rc}"
}

case "${1:-}" in
--self-test) self_test ;;
--integrity) integrity ;;
--vendored)
	[[ $# == 6 && "$3" == --classes && "$5" == --source ]] || die2 "usage: $0 --vendored DIR --classes FILE --source DIR"
	compare "$2" "$4" "$6" strict source
	;;
"")
	rc=0
	integrity || rc=1
	# Not in a || list, so set -e stays active inside live; keep the worse code.
	set +e
	(set -e; live)
	lrc=$?
	set -e
	if ((lrc > rc)); then rc=${lrc}; fi
	exit "${rc}"
	;;
*) die2 "usage: $0 [--self-test | --integrity | --vendored DIR --classes FILE --source DIR]" ;;
esac
