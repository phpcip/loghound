# Privacy

Loghound is self-hosted. **No data leaves your machine except the enrichment lookups
listed below, and every one of them can be turned off.** There is no Loghound company, no
telemetry, no phone-home, no vendor with a copy of your traffic.

That makes almost every privacy question here *your* decision rather than ours. This
document says exactly what is collected so you can make it.

- [Exactly what is collected](#exactly-what-is-collected)
- [What is never collected](#what-is-never-collected)
- [Cookies](#cookies)
- [The three IP modes](#the-three-ip-modes)
- [What leaves your server](#what-leaves-your-server)
- [Retention](#retention)
- [GDPR posture](#gdpr-posture)
- [Data subject requests](#data-subject-requests)
- [What to tell your users](#what-to-tell-your-users)

---

## Exactly what is collected

### From your access logs (plane 1)

Everything here is already in the log file your web server writes. Loghound parses and
indexes it; it does not create it.

| Field | Example | Personal data? |
|---|---|---|
| `ip_s` | `203.0.113.44` | **Yes** — subject to the IP mode below |
| `ip_net_s` | `203.0.113.0/24` | Weakly |
| `ts` | `2026-09-10T09:57:08Z` | With other fields, yes |
| `host_s` `path_s` `query_s` | `/account/settings?id=42` | **Potentially — see the warning below** |
| `method_s` `status_i` `bytes_l` `dur_us_l` `proto_s` | `GET` `200` `152381` | No |
| `ua_s` `ua_hash_s` | `Mozilla/5.0 (X11; Linux…)` | Contributes to a fingerprint |
| `referer_s` `referer_host_s` | `https://www.google.com/` | **Potentially** — referers leak the previous page, sometimes with its query string |
| `accept_s` `accept_lang_s` `accept_enc_s` | `en-GB,en;q=0.9` | Contributes to a fingerprint; language can imply nationality |
| `sec_ch_ua_s` `sec_ch_platform_s` `sec_fetch_*` | `"Chromium";v="152"` | Contributes to a fingerprint |
| `xff_s` | `203.0.113.44, 10.0.0.1` | **Yes** — contains client IPs |
| `tls_proto_s` `tls_cipher_s` | `TLSv1.3` | No |
| `raw_s` | the complete original line | **Yes, everything above at once.** Stored only when `keep_raw` is on |

> **`path_s` and `query_s` deserve your attention.** If your application puts anything
> identifying in a URL — an email in a query string, a password reset token, an order ID, a
> document name — it is in your access log already, and Loghound will index it and make it
> searchable. That is not a change Loghound introduces, but it does make it much easier to
> find. Check what your URLs contain before you index a year of them.

### Derived by Loghound

| Field | How | Notes |
|---|---|---|
| `fp_hash_s` | SHA-1 of the normalised header tuple, **excluding the IP** | A device/browser-configuration fingerprint. It is not unique to a person: everyone running the same browser build with the same settings shares it. |
| `visitor_s` | Hash of `ip_net` + `ua_hash` + `accept_lang` | A coarse, non-cookie visitor identifier. Daily-salted in `hash` mode, so it cannot be correlated across days. |
| `session_id_s` | `sha1(client_key + first_ts + random)` | Groups a visit. Server-side only. |
| `kind_s` `asset_kind_s` `path_depth_i` | Classification of the request | No personal content |
| `bot_score_f` `bot_verdict_s` `bot_reasons_ss` `bot_class_s` | The ruleset | An assessment *about* a visitor |

### From enrichment

| Field | Source | Sent upstream |
|---|---|---|
| `country_s` `region_s` `city_s` `geo_p` `tz_s` | ezcmd geolocation | **The IP address** |
| `asn_i` `as_org_s` `as_type_s` | Team Cymru | **The IP address** |
| `netname_s` | RIR whois | **The IP address** |
| `rdns_s` `rdns_ok_b` | Your DNS resolver | **The IP address** |
| `browser_s` `browser_ver_i` `os_s` `device_s` `ua_bot_*` `ai_crawler_b` | Local UA parsing | Nothing |

Each is individually switchable in `config/loghound.php` under `enrich`. All results are
cached in SQLite (geo/ASN/whois ≥ 30 days, rDNS ≥ 7), including negative results, so a
repeat visitor's address is looked up once per cache window rather than once per request.

### From the beacon (plane 3)

Only if you add `b.js` to your site. It is optional and Loghound works without it.

| Field | What it is |
|---|---|
| `wall_ms` `visible_ms` `engaged_ms` | Three distinct durations — see [README](../README.md) |
| `interactions_i` | A **count** of interaction events |
| `max_scroll_pct_i` | How far down the page the visitor got |
| `pageviews_i` | Pages in this session |
| `js_b` `headless_b` `automation_ss` `ua_claim_ok_b` | Automation and headless indicators |
| `tz_match_b` | Whether the browser timezone agrees with the IP-derived one |
| `webgl_s` | The WebGL `UNMASKED_RENDERER` string |
| `client_score_f` | The execution-plane sub-score |

**The beacon does not record keystrokes, form contents, clipboard, page text, mouse
coordinates, or anything you typed.** It records that interaction *happened*, how much, and
what kind — a count and a scroll depth, not a recording. There is no session replay in
Loghound and there is no plan to add one.

---

## What is never collected

- **No session replay.** No DOM recording, no mouse-path recording, no screen capture.
- **No keystrokes, no form field values, no clipboard.**
- **No page content.** Loghound never reads the body of your pages.
- **No cross-site tracking.** There is no shared identifier, no third-party domain, no
  cookie sync, no data broker, nothing to join against.
- **No third-party ad or analytics network.** The beacon talks to your server and no other.
- **No email addresses, names or account identifiers** — unless your own URLs contain them,
  in which case see the warning above.
- **No telemetry to the Loghound project.** There is nothing to send it to.

---

## Cookies

**The beacon sets no cookies by default.** Visitor identity is a derived hash
(`visitor_s`), not a stored identifier, and that is documented as such rather than
presented as anonymous.

The panel sets one session cookie for logged-in operators when `auth.mode = 'session'`.
That is an authentication cookie for *your* administrators, not a visitor cookie, and it
never touches the sites being measured.

A cookie mode may be offered in future for more accurate returning-visitor counts. If it
ever exists it will be **opt-in and off by default**, because a tool that quietly starts
setting cookies has broken its promise.

---

## The three IP modes

`privacy.ip_mode` in `config/loghound.php`. The setup wizard asks about it prominently.

### `full` (default)

The address is stored as-is.

- Best detection. `fp_ips_24h_i` counts truly distinct addresses, so the proxy-fleet
  signal is at full strength.
- Full geo precision, exact per-IP forensics, straightforward abuse reporting.
- **Personal data under GDPR.** You need a lawful basis.

Default because **you already have the raw address in your own access logs**, indefinitely,
by default. Loghound storing it changes your exposure far less than people assume — the
liability was already sitting in `/var/log`.

### `truncate`

IPv4 → `/24`, IPv6 → `/48`. `203.0.113.44` becomes `203.0.113.0/24`.

- Country- and city-level geo still work; ASN and netname still work.
- **Detection cost:** the fingerprint-cluster rule counts *distinct* IPs. Truncation merges
  a proxy fleet's exits that happen to share a `/24`, so `fp_ips_24h_i` under-counts and
  a fleet can slip below the threshold of 5. It also merges unrelated people who share a
  `/24`, which pushes in the other direction. Expect somewhat noisier verdicts.
- A defensible middle ground for most people. Widely accepted as pseudonymisation; note
  that a `/24` with one household in it is not truly anonymous.

### `hash`

`HMAC-SHA256(ip, salt + today's date)`, truncated. **The salt rotates daily.**

- **Cross-day correlation of an individual becomes impossible**, which is the strongest
  privacy property available while keeping same-day sessions working.
- Same-day sessionisation, cluster detection and per-session forensics all still work.
- **Lost:** geolocation, ASN, netname and rDNS (there is no address left to look up), so
  the Networks and geo views go dark and the ASN-based rules cannot fire. Abuse reporting
  becomes impossible.
- **The salt is the whole protection.** With it, the IPv4 space is small enough to brute
  force in seconds. Treat `privacy.ip_salt` like a password.

### Summary

| | `full` | `truncate` | `hash` |
|---|---|---|---|
| Bot detection quality | best | good | reduced |
| Geo / ASN / rDNS | yes | yes | **no** |
| Cross-day correlation of a person | possible | partly | **no** |
| Abuse reporting | yes | approximately | no |
| GDPR: personal data? | **yes** | pseudonymised | pseudonymised, strongly |

Changing the mode affects **new** documents only. It does not rewrite history — see the
next section for how to remove what is already there.

---

## What leaves your server

Everything, in one list:

| Destination | What is sent | Turn it off with |
|---|---|---|
| ezcmd geolocation | visitor IP addresses | `enrich.geo_enabled = false` |
| Team Cymru | visitor IP addresses | `enrich.asn_enabled = false` |
| RIR whois servers | visitor IP addresses | `enrich.whois_enabled = false` |
| Your DNS resolver | visitor IP addresses (reverse lookups) | `enrich.rdns_enabled = false` |
| Your Solr | **everything** — if you use managed Opensolr rather than your own | `solr.mode = 'custom'` |

**With all four enrichers off and your own Solr, nothing leaves the machine.** Loghound
still works: it loses geo, ASN, netname and rDNS, which costs you the Networks view and
two of the seventeen rules. Everything on the behavioural and execution planes is
unaffected.

**If you use managed Opensolr, your indexes live on Opensolr's infrastructure.** That is a
processor relationship and you should treat it as one in your records.

---

## Retention

`privacy.retention_days` (default **90**, `0` disables deletion). `loghound-retention`
runs daily and issues a real `delete-by-query` — this is a deletion job that actually
deletes, not a paragraph of documentation saying you ought to.

Also purged: expired enrichment cache entries, closed sessions and merged beacon rows in
SQLite.

`privacy.rollup_forever` (default on) keeps the daily rollup documents indefinitely. Those
are aggregate counts with no per-visitor field in them, so long-term trends survive the
deletion of the underlying detail.

**Your web server's own retention is a separate thing, and it is often much shorter.**
Loghound can only ever see as far back as the log files that exist. Check what your box
actually does — see the log-retention section of [INSTALL.md](INSTALL.md), including the
`find -mtime +10 -delete` cron that was on the first box this was deployed to.

**To delete data now**, rather than waiting for the timer:

```bash
sudo -u loghound php <prefix>/bin/loghound-retention
```

---

## GDPR posture

Not legal advice. This is written by an engineer so that your lawyer has something
accurate to read.

**Roles.** You are the **controller**. Loghound is software, not a service, and there is no
Loghound entity that processes anything. If you use managed Opensolr, Opensolr is a
**processor** and you need the usual paperwork with them. If you self-host Solr, there is
no processor at all.

**Lawful basis.** Server-log analytics is commonly run under **legitimate interest**
(Art. 6(1)(f)) — security, abuse prevention, and understanding your own service. That is
easier to argue for Loghound than for most analytics because:

- it processes logs you already generate and already keep;
- it sets no cookies and does no cross-site tracking, so there is nothing to join against;
- there is no third-party recipient at all in the self-hosted, enrichment-off configuration;
- a substantial part of its purpose is **security** — detecting automated abuse — which is
  explicitly recognised as a legitimate interest in Recital 49.

Do a Legitimate Interests Assessment and write it down. `truncate` or `hash` mode makes it
considerably easier to argue.

**ePrivacy / the cookie banner.** The ePrivacy Directive concerns storing or accessing
information *on the user's device*. The beacon by default **stores nothing** on the device:
no cookie, no `localStorage`, no `sessionStorage`. On the common reading, that means no
consent banner is required for it. This is a real and contested area of law and national
regulators differ — the CNIL's exemption criteria are the usual reference point. Check your
own jurisdiction; do not take this paragraph as settled.

**Transparency (Art. 13/14).** Your privacy notice must say you do this. Draft text below.

**Data minimisation (Art. 5(1)(c)).** Choose the IP mode and retention window you can
justify, not the maximum the software allows. Turn off `keep_raw` unless you actually need
retroactive rescoring — it doubles storage and keeps a complete copy of every request line.

**Records of processing (Art. 30).** The tables above are written to be pasted into one.

**DPIA.** Unlikely to be required for ordinary server-log analytics. Consider one if you
run `full` IP mode with long retention on a site processing special-category data, or if
you use the bot verdicts to make automated decisions that affect people.

**Automated decision-making (Art. 22).** Loghound *classifies* traffic; it does not act on
it. If you wire `bot_verdict_s` into something that blocks people, that is your automated
decision and Art. 22 becomes your problem. Note that `bot_reasons_ss` exists partly so such
a decision can be explained — which is a legal requirement as well as good engineering.

---

## Data subject requests

**Access / erasure by IP** — only possible in `full` or `truncate` mode. In `hash` mode
you cannot identify the subject's records, which is by design and is worth saying in your
response.

```bash
# Find what you hold. Use the panel's session explorer, or query Solr directly.
# In truncate mode, search the /24 rather than the address.

# Erase. delete-by-query against both cores, on ip_s.
# There is no CLI flag for this in v1 — do it through your Solr admin, and
# note that the same address will be re-ingested if it is still in your
# access log files, which are the upstream source.
```

**Do the log files first.** Loghound is downstream of `/var/log`. Deleting from Solr while
the original line is still on disk means it comes back the next time you replay. Erasure
has to cover both.

**Objection to processing.** There is no per-visitor opt-out mechanism in v1. The practical
answer is to exclude the requester's address at the source — a `SetEnvIf`/`CustomLog env=`
condition in your web server, which stops the line being written at all.

---

## What to tell your users

Adapt; do not paste verbatim without reading it against your actual configuration.

> ### Server logs and analytics
>
> We analyse our own web server logs to understand how this site is used and to detect
> automated abuse. This is done with self-hosted software running on our own
> infrastructure. We do not use Google Analytics or any third-party analytics service, and
> we do not sell or share this data.
>
> **What we record.** For each request: the IP address, the date and time, the page
> requested, the HTTP status and size, the browser's User-Agent string, the referring page,
> and a small number of standard request headers.
>
> **A small script on our pages** measures how long a page was actually visible and whether
> it was being interacted with, so that we can tell real reading time from a tab left open
> in the background. It also runs technical checks that help us identify automated traffic.
> **It sets no cookies and stores nothing on your device.** It does not record what you
> type, what you click on, your mouse movements, or the contents of any page.
>
> **IP addresses.** [Choose one:]
> - *(full)* We store IP addresses in full, and use them to identify and block abuse.
> - *(truncate)* We shorten IP addresses before storing them (removing the last part), so
>   they identify a network rather than a device.
> - *(hash)* We do not store IP addresses. They are replaced with an irreversible code that
>   changes daily, so activity cannot be linked across days.
>
> **How long we keep it.** [N] days, after which it is automatically deleted. We keep
> anonymous daily totals — visit counts and similar — for longer.
>
> **Third parties.** [Choose:]
> - *(enrichment on)* IP addresses are sent to a geolocation and network-lookup service to
>   determine the approximate country and network operator. No other data is shared.
> - *(enrichment off)* No data is shared with any third party.
>
> **Legal basis.** Our legitimate interest in operating, securing and improving this
> service (GDPR Art. 6(1)(f)).
>
> **Your rights.** You can ask what we hold about you and ask us to delete it. Contact
> [your contact]. Please note that if we do not store IP addresses in an identifiable form,
> we may not be able to locate records relating to you.

### If you want to be a good citizen

- Say it in plain language, near the top, not in clause 14(c).
- If you switch to `hash` mode, say so — it is a real commitment and it is worth the credit.
- If you turn enrichment off entirely, say that too. "No data leaves our servers" is a
  strong and true claim in that configuration, and very few analytics setups can make it.
