# Loghound — Solr schema

Two cores, Solr 9.x, classic single-core indexes (not SolrCloud). Both configsets declare
`version="1.6"` in their `<schema>` element — that is the schema format version, not a Solr
version; nothing here pins a Solr point release.

| Core | One document per | Queried by |
|---|---|---|
| hits | log line | the session drill-down, and the fingerprint facet the scorer runs |
| sessions | session, plus one per day for the rollup | everything else in the dashboard |

**The two cores are named per installation, not `loghound_hits` and `loghound_sessions`.**
Opensolr index names live in a namespace shared by every account on the platform, are
permanent once created, and must match `[a-zA-Z0-9_]`. So `Config::coreName()` builds
`loghound_<install id>_hits` and `loghound_<install id>_sessions` from one 8-hex install id
shared by the pair — for example `loghound_9f3c17ab_hits`. The names are written into
`solr.hits_core` / `solr.sessions_core` at setup and everything else reads them from there;
nothing in the code or in either configset hardcodes a core name. There is no setting, prompt
or environment variable that lets you supply one.

Configset files, three per role:
`solr/hits/conf/{mapping-ISOLatin1Accent.txt,schema.xml,solrconfig.xml}` and the same three
under `solr/sessions/conf/`. All are heavily commented; this document is the operator-facing
version of the same reasoning, plus the numbers.

**A classic schema, not a managed one.** `solrconfig.xml` declares
`ClassicIndexSchemaFactory`, so Solr reads `schema.xml` and never rewrites it. Under the
default managed factory Solr owns the file and the Schema API can change fields underneath an
installation — which means what this release uploads is not authoritative and the only evidence
is a diff nobody runs. For a product whose job is to be trustworthy about what its numbers
mean, a schema the tool cannot guarantee it shipped is not acceptable. The file in
`solr/<role>/conf/` **is** the schema on the index, or the push failed and said so.

**How these files reach Solr, and in what order.** You do not install them. Setup **uploads them
to Opensolr**, one at a time, and the platform reloads the core after each one — so the order is
a safety property and it is **dependencies before dependants**:

1. `mapping-ISOLatin1Accent.txt` — `schema.xml`'s char filter names it. A schema landing first
   would reload the core against a missing file and **the core would not load at all**, which is
   worse than being out of date.
2. `schema.xml` — inert while the index is still on the managed factory, which is exactly what
   makes this step safe during the one-time switch.
3. `solrconfig.xml` — its reload is the one that makes `schema.xml` authoritative.

Every intermediate state loads, and a rejection at any step leaves the index running the
configset it had, so a re-run is always safe. `bin/loghound-schema` names which step failed and
what state that leaves the index in.

This is the reason Loghound requires an Opensolr account and no longer offers to point at a Solr
you run yourself: it owns these two indexes, it has to be able to create them and keep their
schema right, and it cannot do that on a Solr it does not administer. The configsets below are exactly
what gets pushed, so everything this document describes is what is running.

**After an upgrade, they are what gets pushed AGAIN — run `bin/loghound-schema`.** Setup
uploads these files once, when the indexes are created. Nothing re-uploads them afterwards, so
a release that adds a field to this document ships code writing a field your live schema does
not declare. Read rule 4 below and what it costs: the one dynamic field either schema has is
`*` mapped to `ignored`, which means Solr **accepts** that document, discards the value, and
returns no error to anyone. `bin/loghound-schema` compares this checkout against the live
schemas and names what is missing; `bin/loghound-schema --apply` pushes the configsets, schema
first, additively, without touching a document already in the index. The panel's Settings page
carries the same verdict. See [INSTALL.md § Upgrading](INSTALL.md#upgrading).

**Field names are a contract** (SPEC §4). The parser writes them, the scorer reads them, the
dashboard queries them. Renaming one is a breaking change to three components at once.

---

## 1. The four rules this schema follows

**1. `stored="false"` by default; retrieve from docValues.**
The dashboard facets and sorts on nearly every field, so docValues is being paid for
regardless. Storing as well writes the value a second time, into the `.fdt` stream. Only
fields a human reads in the drill-down are stored.

**2. `omitNorms="true"` on every string field.**
Norms are one byte per document per field, used for length normalisation during relevance
scoring. Nothing here is ranked on a string field — they are filtered and faceted. At the
`hits` core's 46 string fields and 10 million documents that is 460 MB of nothing.

**3. `omitTermFreqAndPositions="true"` on every string field.**
Term frequencies and position lists exist to answer "how often" and "how near". An exact
match on `ip_s` needs neither. Roughly halves the postings size for those fields. (Solr 9
already defaults to this for `StrField`; it is written out so the decision is visible.)

**4. No stock sprawl.**
Solr's default configset ships a `_text_` catchall plus about thirty dynamic fields and a
`copyField "*" -> "_text_"`. On a schema with seventy named fields (`hits`; `sessions` has
106) that copyField indexes every value a second time and `_text_` becomes the largest
single component of the index —
for a catchall nothing in Loghound queries. Both are deleted. One catch-all dynamic field
remains, routing anything unrecognised into a type that indexes and stores nothing; see
§6 for why that tradeoff was chosen.

---

## 2. Core `hits`

`uniqueKey` is `id`. Columns: **I** indexed, **DV** docValues, **S** stored.

### Identity and time

| Field | Type | I | DV | S | Why it exists | What it costs |
|---|---|:-:|:-:|:-:|---|---|
| `id` | string | ✓ | | ✓ | `sha1(file + byte offset)`. Deterministic, so replaying a rotated file overwrites instead of duplicating — idempotent re-ingest is the whole reason this is not a UUID. | 40 bytes of pure entropy per doc. **No docValues**: nothing sorts or facets on it, and adding DV would cost ~40 MB/M docs to buy nothing. |
| `ts` | pdate | ✓ | ✓ | ✓ | Request time, UTC. Every range filter and every hourly histogram. | ~8 B DV; barely compressible because it is unique per doc. |
| `host_s` | string | ✓ | ✓ | | Virtual host (`%v`). Multi-site installs filter on it. | ~1 B DV (a handful of distinct values). |
| `src_s` | string | ✓ | ✓ | | Which configured log file the line came from. Lets you prove a source is alive, and lets a mis-detected format be deleted by query. | ~1 B DV. |

### Network

| Field | Type | I | DV | S | Why it exists | What it costs |
|---|---|:-:|:-:|:-:|---|---|
| `ip_s` | string | ✓ | ✓ | ✓ | Subject to `privacy.ip_mode`. `unique(ip_s)` per fingerprint is the product's headline metric, and the cluster view lists the member addresses. | The most expensive docValues field here: ~3 B ordinal plus a large term dictionary. Non-negotiable. |
| `ip_ver_i` | pint | | ✓ | | 4 or 6. | ~0.2 B. DV-only: never filtered on its own. |
| `ip_net_s` | string | ✓ | ✓ | | /24 or /48. The cheap clustering key, and half of the sessionisation key. | ~2 B. |
| `asn_i` | pint | ✓ | ✓ | | ASN. | ~2 B. |
| `as_org_s` | string | ✓ | ✓ | ✓ | Network operator name. Stored because the networks view and the cluster drill-down both print it. | ~2 B DV + ~15 B stored (compressed). |
| `as_type_s` | string | ✓ | ✓ | | `isp\|hosting\|vpn\|edu\|gov\|mobile\|unknown`. Load-bearing: `hosting_asn_browser_ua` and `fp_cluster_proxy_fleet` both read it. | ~1 B. |
| `netname_s` | string | ✓ | ✓ | | RIR netname. Catches leased ranges that share an ASN with legitimate traffic — a residential-proxy operator renting space inside a consumer ISP shows up here and nowhere else. | ~2 B. |
| `rdns_s` | string | ✓ | ✓ | | PTR record. | ~3 B. |
| `rdns_ok_b` | boolean | ✓ | ✓ | | Forward-confirmed rDNS passed. The only honest way to verify a Googlebot claim; `rdns_claim_failed` (weight 95) depends on it. | ~1 B. |
| `country_s` `region_s` `city_s` | string | ✓ | ✓ | | Geo, from the Opensolr geolocation endpoint. `country_s` falls back to the country Team Cymru returns with the ASN, so it is populated far more often than the other two — including with the geolocation endpoint disabled or down. | ~1 / ~2 / ~2 B. |
| `geo_p` | location | ✓ | | | lat,lon. Answers bounding-box and heatmap facets. **Absent when the service returned only a country-level centroid** (`37.751,-97.822`) with no city, and for `0,0` — so the map is sparser than the country facet, deliberately. | BKD points only. **Cannot be retrieved or sorted by distance as shipped** — see §5. |
| `tz_s` | string | ✓ | ✓ | | IANA timezone, compared against the browser's own `Intl` timezone by `tz_mismatch`. From the service when it names one, otherwise derived from `country_s` for the 216 territories with exactly one IANA zone. Absent for a multi-zone country. | ~1 B. |

### Request

| Field | Type | I | DV | S | Why it exists | What it costs |
|---|---|:-:|:-:|:-:|---|---|
| `method_s` | string | ✓ | ✓ | | | ~0.5 B. |
| `path_s` | string | ✓ | ✓ | ✓ | Path with the query string removed. The top-pages table and the drill-down timeline. | ~3 B DV + term dict + ~12 B stored. |
| `path_depth_i` | pint | | ✓ | | Cheap proxy for "how deep did this client dig" — separates a scraper walking a tree from a visitor reading one article. | ~0.3 B. |
| `query_s` | string | | | ✓ | **STORED ONLY.** Query strings are unbounded attacker-controlled text, essentially unique per request; indexing them would build a term dictionary the size of the corpus and faceting on it would be meaningless. | ~15 B stored. |
| `proto_s` | string | ✓ | ✓ | | `HTTP/1.1`, `HTTP/2`. Part of the fingerprint tuple. | ~0.5 B. |
| `status_i` | pint | ✓ | ✓ | ✓ | The exact code, which is what an investigator asks for — 403 apart from 401. A first-class filterable dimension. | ~1 B. |
| `status_class_s` | string | ✓ | ✓ | | `2xx\|3xx\|4xx\|5xx`. The question an **operator** asks, as a term: was it answered, redirected, refused, or did it break. A range filter on `status_i` cannot be a facet; this can, in four buckets. Written by the same branch that writes `status_i`, so absent means "not recorded" on both and never `1xx`. | ~0.5 B. |
| `bytes_l` | plong | | ✓ | | Summed and percentiled, never filtered alone, so DV-only — no BKD tree. | ~2 B. |
| `dur_us_l` | plong | ✓ | ✓ | | From `%D`. **ABSENT when `%D` is not logged** — never zero, because a zero would drag every latency percentile toward the floor. | ~2 B when present, 0 when absent. **Indexed** since the Attacks release: Panel\Performance sends `dur_us_l:[* TO *]` as a facet sub-query on every page load, and a docValues-only field answers that with an uninverted full scan. |
| `kind_s` | string | ✓ | ✓ | | `html\|asset\|api\|beacon\|robots\|favicon\|other`. Drives the page count and `asset_ratio_f`, both of which feed scoring. **`asset` and `favicon` documents are not written to the index at all** unless `ingest.index_assets` is on: they are still parsed, enriched, attack-matched and counted into their session, so every session figure sees the complete traffic — only the per-request document is refused. See `ingest.index_assets` in the config. | ~1 B. |
| `asset_kind_s` | string | ✓ | ✓ | | `js\|css\|img\|font\|media\|map`. Only set when `kind_s=asset`. | ~1 B. |

### Client

| Field | Type | I | DV | S | Why it exists | What it costs |
|---|---|:-:|:-:|:-:|---|---|
| `ua_s` | string | ✓ | ✓ | ✓ | Raw User-Agent. Every forensic view prints it. | ~3 B DV + large term dict + ~20 B stored (UA strings compress extremely well — they repeat thousands of times). |
| `ua_hash_s` | string | ✓ | ✓ | | Half the sessionisation key, and a grouping key that avoids dragging 200-byte strings through aggregations. | ~3 B. |
| `browser_s` `browser_ver_i` `os_s` `device_s` | string/pint | ✓ | ✓ | | Parsed UA. `device_s`: `desktop\|mobile\|tablet\|bot\|unknown`. | ~1 B each. |
| `ua_bot_b` `ua_bot_name_s` `ua_bot_cat_s` | | ✓ | ✓ | | The UA **claims** to be a bot. A claim, not a fact — anyone can send it and anyone can omit it. Never used alone except for the honest-crawler classification, which additionally requires verified rDNS. | ~1 B each. |
| `ai_crawler_b` | boolean | ✓ | ✓ | | Its own field rather than `ua_bot_cat_s=ai` because "how much of my traffic is LLM crawlers" is asked constantly and deserves a one-term filter. | ~1 B. |

### Headers

Present only when the operator logs them. **ABSENT, never empty-string**, when they are not:
an empty string is a real value that facets, sorts and matches, and it would make "no
`Accept-Language` header" indistinguishable from "`Accept-Language: ''`". Two rules worth 70+
points turn on exactly that distinction (`ua_secch_mismatch`, `platform_mismatch`), and both
go silent rather than guessing — see `Signals::headerLogged()`.

| Field | Type | I | DV | S | Notes |
|---|---|:-:|:-:|:-:|---|
| `referer_s` | string | ✓ | ✓ | ✓ | Stored: the traffic-sources view prints it. |
| `referer_host_s` `referer_type_s` | string | ✓ | ✓ | | `direct\|search\|social\|ai\|internal\|link\|ad`. |
| `accept_s` `accept_lang_s` `accept_enc_s` | string | ✓ | ✓ | | High-value fingerprint components. `accept_lang_s` in particular carries a lot of entropy across real humans, which is what keeps `fp_hash_s` discriminating. |
| `sec_ch_ua_s` `sec_ch_platform_s` `sec_ch_mobile_b` | | ✓ | ✓ | | Client hints. Chromium has sent these since v89 on secure contexts. |
| `sec_fetch_site_s` `sec_fetch_mode_s` `sec_fetch_dest_s` `sec_fetch_user_s` | string | ✓ | ✓ | | `Sec-Fetch-Dest` is by far the most reliable way to tell a document navigation from a sub-resource — worth logging for that alone. |
| `xff_s` | string | ✓ | ✓ | | |
| `tls_proto_s` `tls_cipher_s` | string | ✓ | ✓ | | Also used to suppress `ua_secch_mismatch` on plain-HTTP requests, where the browser correctly sends no client hints. |
| `ja4_s` | string | ✓ | ✓ | | **Nothing writes this in v1.** It needs a HAProxy in front exporting the fingerprint into a header. Defined now so enabling it later is a config change, not a reindex. An always-absent field costs zero bytes. |

### Fingerprints and session

| Field | Type | I | DV | S | Notes |
|---|---|:-:|:-:|:-:|---|
| `fp_hash_s` | string | ✓ | ✓ | | **The cluster key.** sha1 of the normalised header tuple: `ua`, `accept`, `accept_lang`, `accept_enc`, `sec_ch_ua`, `sec_ch_platform`, `sec_fetch_*`, `proto`. **Excludes the IP by design** — see §4. |
| `session_id_s` | string | ✓ | ✓ | ✓ | Assigned at ingest. Stored so a hit links back to its session without a second lookup. |
| `session_seq_i` | pint | | ✓ | | 1-based position in the session; orders the timeline, never filters. |
| `visitor_s` | string | ✓ | ✓ | | `ip_net + ua_hash + accept_lang`, daily-salted in `hash` privacy mode. **"Stable-ish"**: survives a session boundary but not a network change or a browser update. It is not a person and the UI must never label it one. |
| `hit_flags_ss` | strings | ✓ | ✓ | ✓ | Signal codes fired by this single hit — today, the attack patterns in `Score\Attacks` (see [ATTACKS.md](ATTACKS.md)). The **final** bot verdict lives on the session document; a hit alone almost never carries enough context, and pretending otherwise is how tools end up flagging a favicon request as a bot. |
| `hit_rules_i` | pint | ✓ | ✓ | | The version of the per-hit rule table that judged this request. **The third state**: absent means *never evaluated*, which is not the same as clean. Present with no `hit_flags_ss` means evaluated and nothing matched. Without it the Attacks view would report a deployment gap as a quiet week. | ~1 B. |

### Raw

| Field | Type | I | DV | S | Notes |
|---|---|:-:|:-:|:-:|---|
| `raw_s` | string | | | ✓ | **Stored, not indexed, no docValues.** |

Why keep it: scoring rules change. `rule_version_i` tells you which ruleset produced a
historical verdict; `raw_s` lets you re-derive the whole document under a new one. That is
retroactive rescoring, and it is the difference between "we improved the detector" and "we
improved the detector, starting from today".

What it costs: roughly your log file, minus compression. SPEC §4.1 warns it "roughly doubles
index size"; that assumes no compression. With `BEST_COMPRESSION` (see §3) on real log text,
expect **4–6x**, which lands at 55–80 bytes per apache-`combined` line and 130–200 bytes per
recommended-LogFormat line. In practice a **20–35% increase in total index size**. Turn it
off with `ingest.keep_raw = false` and the field simply stops being written.

### Catchall

`ingest.catchall`, default on. **The first thing to turn off at high volume.** It is the only
place in the schema that pays for term frequencies and positions, and it re-indexes bytes
that are already indexed as strings.

Two layers, not redundant by accident:

* the `*_txt` fields are what edismax actually searches, via
  `qf = path_txt^3 ua_txt^2 as_org_txt^2 netname_txt^2 rdns_txt city_txt country_txt`.
  Separate fields are what make per-field boosting possible.
* `text_all` is the single-field fallback used as `df` for a bare query. It is *nearly* a
  duplicate of the `*_txt` fields, with one deliberate difference on each core: `text_all`
  also receives `referer_s`, which no `*_txt` field gets, so a bare query can find a session
  by where it came from.

On `sessions` the sources differ too: `path_txt` and `text_all` are fed from `paths_ss` (the
capped per-session path list), not from a `path_s` that does not exist there. So a free-text
path search on the explorer searches the sample of up to 50 paths the scorer kept, and a
session that touched more than that can be missed by a path query even though the path is
counted in `uniq_paths_i`.

**If you need to cut, drop `text_all` first.** You keep full search through the `qf` and lose
only the bare-query fallback. It is about half the catchall's cost.

Fed by copyField: `path_s`, `ua_s`, `referer_s`, `as_org_s`, `netname_s`, `country_s`,
`city_s`, `rdns_s`.

---

## 3. Core `sessions`

`uniqueKey` is `id`. Two document types share the core, separated by `doc_type_s`:

* `doc_type_s = "session"` — `id` is the session id.
* `doc_type_s = "rollup_daily"` — `id` is `rollup_daily:YYYY-MM-DD`.

> **Note on the spec.** SPEC §4 says "two cores"; SPEC §10 refers to a `rollup_daily` source
> without saying where it lives. Putting it in this core is the reading that satisfies both:
> a rollup is a session-shaped aggregate queried by the same views, and a third core would
> triple the provisioning for a few hundred documents a year. **Every dashboard query must
> carry `fq=doc_type_s:session` (or `:rollup_daily`).**

### Session rollup

`ts_start` `ts_end` (pdate, I/DV/S) · `hits_i` `pages_i` `assets_i` `uniq_paths_i` (pint,
I/DV) · `bytes_l` (plong, DV) · `status_2xx_i` `_3xx_i` `_4xx_i` `_5xx_i` (pint, I/DV) ·
`got_304_b` (boolean, I/DV) · `entry_path_s` `exit_path_s` (string, I/DV/S) ·
`paths_ss` (strings, I/DV/S) · `hit_flags_ss` (strings, I/DV/S) · `hit_rules_i` (pint, I/DV).

The four status counters are **indexed**, so "sessions that received at least one 5xx" is a
filter. That is deliberately *not* the same question as "requests that returned 5xx", which is a
hits question and is what the Attacks view asks: a session that recorded one 2xx and one 4xx
says nothing about which of its requests was which. The panel never blurs the two.

`hit_flags_ss` is the **union** of the attack patterns this session's requests matched, and
`hit_rules_i` says the session was evaluated at all. Both follow the three-state rule: absent
means never evaluated, never "clean". See [ATTACKS.md](ATTACKS.md).

`paths_ss` is **capped at 50** by the scorer. The cap is not cosmetic: a crawler walking
200k URLs would otherwise put 200k terms into one document's `SORTED_SET` docValues, which
is where a document goes from "large" to "breaks the merge". `uniq_paths_i` carries the true
count, so nothing is fabricated — but **the UI must label the list a sample**.
(`uniq_paths_i` itself saturates at 10,000 distinct paths per session; the sessionizer stops
tracking beyond that. No scoring rule uses a threshold anywhere near it.)

The identity, network and client fields the session view needs are denormalised onto the
session from its first hit. That duplication is the point: one query against a core with
10–20x fewer documents answers "bots by ASN" without touching the hit stream.

**Not *every* §2 field, though, and the gap is worth knowing about.** The sessions schema
does not define the per-request fields (`method_s`, `path_s`, `query_s`, `status_i`,
`status_class_s`, `kind_s`, `asset_kind_s`, `dur_us_l`, `session_seq_i`, `raw_s`, `ts`) —
correctly, since they describe one request rather than a visit. `hit_flags_ss` and
`hit_rules_i` are the exception and are defined on **both**, at two grains: on a hit they are
what that request matched, on a session they are the union across its requests, exactly as
`paths_ss` is the union of the hits' `path_s`. Both questions are real and neither substitutes
for the other — see [ATTACKS.md](ATTACKS.md) §2. But it also does not define
the request-header fields: `accept_s`, `accept_enc_s`, the `sec_ch_*` set, the `sec_fetch_*`
set, `tls_proto_s` and `tls_cipher_s`.

That second group is a **live schema/code gap, not a design decision**. `Sessionizer::identityOf()`
puts exactly these ten values into the session's `first` map — `accept_s`, `accept_enc_s`,
`sec_ch_ua_s`, `sec_ch_platform_s`, `sec_ch_mobile_b`, `sec_fetch_site_s`,
`sec_fetch_mode_s`, `sec_fetch_dest_s`, `sec_fetch_user_s`, `tls_proto_s`, `tls_cipher_s` —
and the scorer copies every non-underscore key from it onto the session document, so they
*are* sent to Solr. There the catch-all
`<dynamicField name="*" type="ignored" multiValued="true"/>` swallows them without error.
(`accept_lang_s`, `proto_s`, `host_s`, `src_s`, `ip_ver_i`, `ua_hash_s`, `geo_p` and
`visitor_s` from the same list *are* defined and land correctly.)
This is exactly the quiet degradation §6 warns about, happening today. Nothing depends on
them at the session level (the scoring rules read the hit documents), so the effect is
wasted bytes on the wire rather than a wrong number — but if you want to facet sessions by
`sec_ch_ua_s`, the field has to be added to the sessions schema first.

### Timing — the differentiator

Four numbers that every other tool conflates into one.

| Field | What it is |
|---|---|
| `log_span_ms_l` | Last request minus first. What log-only tools call "time on site". It is really "time between the first and last byte the server saw", and it is structurally blind to the final page of a session. **Present for every session.** |
| `wall_ms_l` | Beacon: page-open wall clock, summed across pageviews. What Clicky/GA report. Includes time the tab spent hidden. |
| `visible_ms_l` | Beacon: `visibilityState === 'visible'` **and** the window focused. |
| `engaged_ms_l` | Beacon: visible **and** within 30 s of a real interaction. The honest number. |

`beacon_b` says whether any beacon arrived. **When it is false the three beacon fields are
ABSENT, never zero.** A zero is a measurement; an absent field is an admission. Solr's
`avg()` skips missing values, which is exactly the behaviour wanted — and it is why every
chart must state its population (SPEC §10: "an unlabelled number is a lie").

A beacon that matched no open log session is recorded as `planes_s: beacon_only`, not as a
suspicion. There used to be a `beacon_orphan_b` for it, described as suspicious in itself; nothing
ever wrote it, and the description had stopped being true — a tailer that is behind, or a site
whose logs have not been read yet, produces beacon-only sessions in bulk and none of them is
evidence of anything. The field and the rule input that read it are gone; `planes_s` states the
same observation without the accusation.

### Behavioural and execution plane

`gap_p50_ms_l` `gap_stddev_ms_l` (plong, I/DV) · `asset_ratio_f` (pfloat, I/DV) ·
`interactions_i` `max_scroll_pct_i` `pageviews_i` (pint, I/DV) ·
`js_b` `headless_b` `ua_claim_ok_b` `tz_match_b` (boolean, I/DV) ·
`automation_ss` (strings, I/DV/S) · `webgl_s` (string, I/DV/S) · `client_score_f` (pfloat, I/DV).

`automation_ss` and `webgl_s` are **stored** because "why did you call this a bot" must be
answerable from the document alone. `"Google SwiftShader"` in a report is worth more than a
boolean: it is the evidence, not the conclusion.

### Cluster and verdict

| Field | Notes |
|---|---|
| `fp_hash_s` | string, I/DV/S. |
| `fp_ips_24h_i` | pint, I/DV/S. Distinct IPs sharing this fingerprint within ±12 h, computed by the scorer with a JSON Facet `unique(ip_s)`. **ABSENT when it could not be computed** — the rule that reads it must not treat absent as 1. |
| `bot_score_f` | pfloat, I/DV/S. 0–100. |
| `bot_verdict_s` | string, I/DV/S. `human\|likely_human\|unknown\|likely_bot\|bot`. |
| `bot_reasons_ss` | strings, I/DV/S. **Never empty.** A clean session carries `no_bot_signals`. The bot-forensics view is essentially a facet on this field. |
| `rule_version_i` | pint, I/DV/S. Bumped on every rule or weight change, so a historical score can be understood and a rescoring pass can find everything judged by an older version. |
| `bot_class_s` | string, I/DV/S. `headless\|scripted\|declared_crawler\|ai_crawler\|monitor\|spoofed_ua\|proxy_fleet\|none`. |

**`declared_crawler` and `ai_crawler` are not threats.** Googlebot and GPTBot are bots, and
they are also the traffic that puts a site in a search index or an LLM answer. The class is a
first-class indexed field, and the separation is enforced in `Rules::classify()` rather than
in the UI, because every consumer — dashboard, export, alert — must see the same split. A UI
checkbox is a suggestion, not a fix.

### Daily rollup fields

`day_s`, `r_sessions_i`, `r_hits_i`, `r_pages_i`, `r_bytes_l`, the verdict distribution
(`r_human_i` … `r_bot_i`), the class distribution (`r_declared_crawler_i`, `r_ai_crawler_i`,
`r_headless_i`, `r_scripted_i`, `r_proxy_fleet_i`, `r_spoofed_ua_i`, `r_monitor_i`), and the
timing sums (`r_wall_ms_sum_l`, `r_visible_ms_sum_l`, `r_engaged_ms_sum_l`,
`r_log_span_ms_sum_l`) alongside **`r_beacon_sessions_i`**, the population those sums cover.

Every number is an aggregate; nothing identifies a visitor. That is what makes
`privacy.rollup_forever` compatible with a 90-day retention policy — the sessions behind a
rollup can be deleted while the shape of the traffic survives.

The rollup is **recomputed** from the sessions core on every scorer run, not incremented. An
atomic `inc` would be one cheap call and it would be wrong: the Solr client retries a request
whose response was lost, and a retried increment double-counts. Recomputing with one facet
query is idempotent, exact, and self-healing.

---

## 3b. What `stored`, `indexed` and docValues each buy, and the audit that set them

Three different questions, three different answers per field:

- **`stored`** — is the value ever read back off a document? (an `fl` list, `sessionFl()`,
  `hitFl()`, or a document read anywhere in `src/`)
- **`indexed`** — is it ever in a `q`, an `fq`, a filterable dimension, or the free-text search?
- **docValues** — is it faceted, sorted, grouped, or used by a function query?

Two things make this easier than it looks. A field with docValues and `stored="false"` is still
**returnable** in Solr 9 (`useDocValuesAsStored` defaults on for these types), so dropping
`stored` where docValues exists costs nothing in behaviour and saves the second copy on disk.
And docValues is the one of the three the panel needs almost everywhere, because nearly every
field here is a facet.

### What changed in the Attacks release, and why

| Field | Core | Before | After | Why |
|---|---|---|---|---|
| `dur_us_l` | hits | `indexed=false` | `indexed=true` | `Panel\Performance` sends `dur_us_l:[* TO *]` as a facet sub-query on **every** page load. It worked — Solr answers from docValues — as an uninverted full scan. This was a live defect, not a tidy-up. |
| `status_2xx_i` … `status_5xx_i` | sessions | `indexed=false` | `indexed=true` | "Sessions that received at least one 5xx" was unaskable. Note this is **not** the same question as "requests that returned 5xx", which is a hits question; the panel keeps the two apart. |
| `ip_s`, `ua_s`, `as_org_s`, `search_terms_ss`, `session_id_s` | hits | `stored=true` | `stored=false` | None of them is in `Query::hitFl()` or read off a hit document anywhere. Only their sessions-core twins are. docValues still returns them. `ua_s` is the big one: ~150 bytes per hit document, written twice. |
| `ua_hash_s`, `visitor_s` | both | `indexed=true` | `indexed=false` | Neither appears in any `q`, `fq`, filter allowlist or copyField. `visitor_s` is only ever `unique(visitor_s)`, which is docValues; `fp_hash_s` is the real clustering key. Two 24–40 character terms per document, for nothing. |
| `geo_p` | both | `docValues=false` | `docValues=true` | 8 bytes a document, and it buys two things that otherwise need a reindex: the point can be **returned** and sorted by distance. A `LatLonPointSpatialField` can never be a facet bucket, so the country-centroid map in `Panel\Networks` stays the correct way to draw the aggregate. |

### What was deliberately left alone

- **`id`** keeps `docValues="false"` on both cores. It is 40 bytes of pure entropy per document
  and nothing facets, sorts or groups on it; at ten million hits that is ~400 MB to buy nothing.
  This is the one place the "docValues on everything" bias loses, and it loses on a measurement.
  *If `session_id_s` is ever added back to the browsable dimension list, `id` needs docValues,
  because the sessions alias points at it.*
- **`query_s`** keeps `indexed=false docValues=false`. Unbounded attacker-controlled text with a
  near-unique value per request; a term dictionary over it would be the size of the corpus. This
  is exactly why attack detection runs at ingest — see [ATTACKS.md](ATTACKS.md) §2.
- **`raw_s`** keeps `stored`-only, for retroactive rescoring.
- **The `text_general` fields** (`text_all`, `path_txt`, `ua_txt`, `as_org_txt`, `netname_txt`,
  `rdns_txt`, `city_txt`, `country_txt`) **cannot take docValues at all.** They are analysed text
  and Lucene has no docValues format for a tokenised field. They are `indexed`-only by necessity.
- **The daily rollup block** (`day_s`, every `r_*` field) is untouched. It is *one document per
  day*, so every byte argument about it is noise, and changing it risks the retention contract
  that makes a 90-day tool able to show you last year.
- Roughly forty fields are `indexed="true"` and are not in any filter today —
  `accept_lang_s`, `tls_cipher_s`, `xff_s`, `ja4_s`, the `sec_fetch_*` set and others. They
  **keep** it. They are string fields with `omitNorms` and `omitTermFreqAndPositions`, so their
  postings are cheap, and this is a forensics tool where "filter by Accept-Language" is a
  plausible next question. Removing `indexed` to save a few percent, at the cost of a reindex
  each time somebody wants one back, is the wrong trade in this direction.

### The disk trade, in both directions

Added: docValues on `geo_p` (8 B/doc on both cores), a BKD tree for `dur_us_l` (~2 B/hit) and
for four session counters, one short term for `status_class_s` (~0.5 B/hit), one small int for
`hit_rules_i` (~1 B/doc), and `hit_flags_ss` — absent on the overwhelming majority of documents,
so effectively free until something matches.

Removed: the stored copies of `ua_s`, `ip_s`, `as_org_s`, `search_terms_ss` and `session_id_s`
on the hits core (the largest single saving here, dominated by `ua_s`), and the postings for
`ua_hash_s` and `visitor_s` on both.

Net on the hits core: a modest **saving**, because one 150-byte stored UA per document outweighs
everything added. On the sessions core: a small increase, on a core with 10–20× fewer documents.

---

## 3c. `text_general`, and what full-text search has to be able to find

The rule this chain is built to: **a person must be able to search for anything they can see on
screen and find it.** `AS263699`. `74.7.175.172`. `opensolr-search`. `Chrome/150`. A fragment of
any of them. That is a different problem from searching prose, and every decision follows from it.

`WordDelimiterGraphFilterFactory` is the whole thing, and its settings are not defaults:
`generateWordParts` + `generateNumberParts` split `AS263699` into `as` and `263699` and
`74.7.175.172` into its four octets; `catenateWords` + `catenateNumbers` + `catenateAll` rejoin
them so `opensolr-search` is also findable as `opensolrsearch`; `splitOnNumerics` separates
letters from digits inside one token; and `preserveOriginal` keeps the whole untouched string
alongside every part, which is what makes an exact paste out of a table match it.
`FlattenGraphFilterFactory` is required after it at **index** time and must not be present at
query time, where the graph is what lets a multi-token expansion match as a phrase.

`WhitespaceTokenizerFactory` rather than `StandardTokenizer`, because the standard tokenizer
applies UAX#29 word rules that throw punctuation away before `WordDelimiterGraph` ever sees it.
Whitespace hands the token over intact.

**What was deliberately left out, and why — this is machine data, not prose:**

| Filter | Verdict | Reason |
|---|---|---|
| `StopFilterFactory` | **removed** | English stopwords on a URL make `/a/`, `/in/`, `/it/` and `/is/` unfindable. A path segment is not a stopword. Also needed an external `stopwords.txt`. |
| `SnowballPorterFilterFactory` | **removed** | Stemming machine data is harmful, not merely useless: `/assets` and `/asset` are different paths, and a stemmer that collides two identifiers is a **false match** in a tool whose job is telling two requests apart. The loss is that searching `crawlers` no longer finds `crawler`. |
| `SynonymGraphFilterFactory` | **removed** | Needs a synonyms file that would be empty. |
| `HTMLStripCharFilterFactory` | **removed** | There is no markup in a log line, and it would eat a `<` that a stored XSS probe put in a path — which is a value this product must be able to find. |
| `ICUTokenizerFactory` | **not used** | Lives in Solr's `analysis-extras` module: present on an Opensolr node, absent from a stock self-hosted Solr. A configset that will not load on half the installations is worse than a slightly coarser tokenizer. |
| `MappingCharFilterFactory` | **kept** | The one external file either configset ships. See `mapping-ISOLatin1Accent.txt` beside the schema, and §2 of this document for why it must be uploaded *before* the schema. |
| `CJKWidthFilterFactory`, `EnglishPossessiveFilterFactory`, `ASCIIFoldingFilterFactory` | kept | Cheap, and none of them can cause a false match. Folding is why a search for `munchen` finds `München`. |
| `LengthFilterFactory`, `RemoveDuplicatesTokenFilterFactory` | kept | The first bounds a hostile 4 KB token; the second is *required*, because `catenateAll` plus `preserveOriginal` emit duplicates constantly. |

The two cores carry byte-identical chains, and a test fails if they drift: the free-text box
searches both planes, and a term that tokenised differently on one of them would find a session
and not its own requests.

---

## 4. `fp_hash_s`, and the honest limitation

The fingerprint deliberately **excludes the IP address**. A fleet on rotating residential
proxies changes its address on every request, so any fingerprint including the address
identifies nothing. What it cannot change without breaking the browser it is impersonating is
the exact header tuple that browser sends. Counting distinct `ip_s` per `fp_hash_s` turns the
fleet's own evasion into its signature.

**The limitation, stated plainly.** The tuple has eleven components. With plain apache
`combined`, nine of them are not logged — only the User-Agent and the protocol version
survive — so `fp_hash_s` degenerates to roughly a hash of those two. That still catches a
fleet using one UA across many addresses. It does **not** catch a fleet that also rotates
its Chrome major version: that fleet splits into one cluster per version, and each cluster
can fall below the ≥5 threshold.

This is measured, not theorised. `tests/fixtures/apache_combined_bot_fleet.log` is a real
capture: 13 IPs across six distinct User-Agent strings spanning five Chrome major versions
(147, 148, 150, 151, 152). From `combined` alone the largest cluster is five addresses — it
trips the rule and those five sessions are correctly classified `bot` / `proxy_fleet` —
while the remaining eight split into clusters of 3, 2, 1, 1 and 1, fire nothing but
`single_page_10s` (15), and are therefore scored **`human`**. Not "unknown": human, the same
verdict a real reader gets. They are caught immediately once the beacon reports
(`tests/test_scoring.php` proves both).

**What to do about it:** log the recommended LogFormat from SPEC §8. `Accept-Language` alone
carries enough entropy across real humans to keep the fingerprint discriminating while the
fleet — which sends one header set — collapses into one cluster.

**What NOT to do:** normalise the browser version out of the UA before hashing. It would
merge the fleet's clusters, and it would also merge every Windows Chrome user on the site
into one cluster of thousands of addresses. On plain `combined` that is not a tuning
decision, it is a switch that labels your entire audience a proxy fleet.

---

## 5. Index size

**These are estimates from field-count arithmetic, not measurements of a live index.** They
are shown as a breakdown so you can check the reasoning and adjust for your own traffic. Real
numbers depend heavily on cardinality: a site with 200 URLs and a site with 2 million URLs
have very different term dictionaries.

### Per million hit documents

| Component | apache `combined` | recommended LogFormat |
|---|---:|---:|
| docValues (~50 fields) | ~105 MB | ~140 MB |
| Inverted index (~40 fields, DOCS_ONLY) | ~60 MB | ~85 MB |
| Stored fields, excluding `raw_s` | ~105 MB | ~110 MB |
| `raw_s` (`ingest.keep_raw`) | ~65 MB | ~165 MB |
| Catchall: 7 × `*_txt` (`ingest.catchall`) | ~125 MB | ~130 MB |
| Catchall: `text_all` (`ingest.catchall`) | ~150 MB | ~155 MB |
| **Total, everything on** | **~0.6 GB** | **~0.79 GB** |
| **Total, `keep_raw=false`, `catchall=false`** | **~0.27 GB** | **~0.34 GB** |

Working: docValues ordinals run 1–3 bytes per field per document depending on cardinality;
`DOCS_ONLY` postings run roughly 1–1.5 bytes per posting plus the term dictionary; stored
fields are the raw bytes divided by the compression ratio; the catchall is about 50 tokens
per document at ~2.5 bytes per posting once term frequencies and positions are included.

An apache `combined` line in the fixtures averages **320 bytes**. The recommended LogFormat
adds twelve more quoted header fields and lands near **800 bytes**.

On compression: `BEST_COMPRESSION` over the human fixture reaches better than 10x, but that
is a 62 KB sample of highly repetitive traffic and it overstates the case. **4–6x is the
figure to plan with** for real log text. `BEST_SPEED` (Lucene's default, which this configset
overrides) gets roughly half that.

### Sessions core

One document per session. At a typical 8–15 hits per session that is 70k–125k session
documents per million hits, at roughly 700 bytes each including the catchall:
**~50–90 MB per million hits.**

Daily rollups are a few hundred bytes each — about 100 KB a year. They are free, which is why
`rollup_forever` defaults on.

### What to turn off, in order

1. **`ingest.catchall = false`.** Biggest single win: ~45% of the hits core. You lose the
   free-text search box in the session explorer; every facet, filter and chart keeps working.
   If you want a middle position, delete `text_all` and its copyFields but keep the `*_txt`
   fields — that recovers about half the saving and keeps edismax search intact.
2. **`ingest.keep_raw = false`.** ~11% on `combined`, ~21% on the recommended format. You
   lose the ability to re-derive documents under a future ruleset.
3. **`privacy.retention_days`.** The only lever that bounds growth rather than reducing a
   constant. `bin/loghound-retention` enforces it, and `rollup_forever` keeps the long-term
   charts alive across the deletions.
4. Drop `query_s` (stored-only, ~15 B/doc) if you never look at query strings.

Note that deleted documents do not return disk immediately — Lucene reclaims on merge. Both
cores set `deletesPctAllowed` so that happens steadily rather than in one stall, and nothing
forces an optimize (a forced merge rewrites the whole index and needs double the disk while
it runs).

---

## 6. Deliberate omissions

**The `_text_` catchall and the stock dynamic fields are deleted.** Solr's default configset
copies every value into `_text_`, which on this schema can be the largest single component of
the index — for a field nothing in Loghound queries.

**One catch-all dynamic field remains:**
`<dynamicField name="*" type="ignored" multiValued="true"/>`. Anything not named in the
schema is silently dropped rather than indexed. `multiValued="true"` is what makes it accept
an array as well as a scalar, so an unexpected list does not fail the request either.

The tradeoff, stated plainly: a schema/code skew degrades quietly. If a future version writes
`foo_bar_s` and you have not pushed the new schema, that value vanishes instead of failing
the request — which is right for a running ingest daemon, because the alternative is a 400
that kills an entire 500-document batch and stalls the tailer. The cost is that a typo in a
field name is silent. **If you are developing new fields, comment that line out** and let
Solr reject them loudly until you are done.

**`geo_p` carries docValues.** It answers bounding-box and heatmap facet queries, and the
docValues let the point be *retrieved* and sorted by distance. This section previously said the
field was indexed-only and told you to switch docValues on yourself — while the table above had
described the switch as already made. The file has now caught up with the table.

There is a second reason beyond retrieval, and it is the one that forced the issue: an atomic
update rebuilds the whole document from what can be read back, so a field that is indexed and
neither stored nor docValues is **silently dropped** by any partial update. `geo_p` was the only
field in either schema in that state which is not a copyField target (Solr refills those from
their sources), so it was the only one that would have quietly lost data.

**No `<lib/>` directives in either solrconfig.** The stock configset loads contrib jars
(Tika/extraction, clustering, langid, velocity, DIH). Every one is an unauthenticated code
path behind a request handler, and Tika in particular has a long history of RCEs triggered by
a hostile document. Loghound needs none of them, and not loading a jar is a stronger control
than not defining its handler.

**No `/stream`, `/sql`, `/export`, `/replication`, `/update/extract`, `/debug/dump`,
`/terms`, `/tvrh`, `/analysis/*`, `/spell`, `/suggest`, `/browse`, `/elevate`.** Each removal
is annotated in `solr/hits/conf/solrconfig.xml` with what it would hand an attacker. The
short version: `/stream` and `/sql` execute a server-side language with HTTP and JDBC
sources; `/export` dumps the entire core in one response; `/replication` serves the raw index
files; `/terms` enumerates the term dictionary, which on this schema means every IP address
and every URL in the index without a query.

**`enableRemoteStreaming="false"` and `enableStreamBody="false"`** are written out
explicitly even though they are the Solr 9 defaults, so that copying a stock config over this
one is a visible change rather than a silent regression. `src/Solr.php` refuses to send any
`stream.*` parameter independently — two locks on the same door, because a config file can be
replaced by an operator restoring a stock configset and the application should still be safe.

---

## 7. Commit and cache settings

Both cores: `autoSoftCommit maxTime=5000`, `autoCommit maxTime=60000 openSearcher=false`
(SPEC §5).

`openSearcher=false` on the hard commit is the important half. It flushes segments to disk
and truncates the transaction log (durability) **without** opening a new searcher (no cache
flush, no warming stall). Visibility is entirely the soft commit's job. Getting this
backwards is the classic way to make a Solr node spend all its time warming.

The two cores differ on caches because their workloads are mirror images:

| | `hits` | `sessions` |
|---|---|---|
| Shape | write-heavy, read-rare, append-only | read-heavy, write-light, facet-dominated |
| `filterCache` | 128, **autowarm 0** | 1024, autowarm 128 |
| `queryResultCache` | 128, **autowarm 0** | 512, autowarm 64 |
| `documentCache` | 256, autowarm 0 | 512, autowarm 0 |
| `useColdSearcher` | true | false |

**Autowarm is 0 everywhere on `hits`.** With a 5-second soft commit a searcher lives for five
seconds; warming it by replaying 128 old filters costs more CPU than the queries it would
serve. Autowarming and near-real-time indexing are mutually exclusive, and near-real-time
wins on the ingest core. On `sessions`, writes arrive once a minute and the dashboard reuses
the same handful of filters on every refresh, so warming pays for itself.

`documentCache` is never autowarmed on either core — internal document ids change with every
searcher, so warming it would populate the cache with wrong answers.

Both cores use `SchemaCodecFactory` with `compressionMode=BEST_COMPRESSION` (DEFLATE) instead
of the default `BEST_SPEED` (LZ4). Log lines are extremely repetitive, so DEFLATE typically
reaches 4–6x on `raw_s` where LZ4 reaches 2–3x. The cost is CPU on stored-field *retrieval*,
and stored fields are retrieved only in the drill-down, one screen at a time. It applies to
newly written segments, so on an existing index the benefit arrives as segments merge.
