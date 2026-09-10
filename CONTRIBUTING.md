# Contributing to Loghound

Thanks for looking. This is a small project with a narrow purpose, and the fastest way to
get a change merged is to understand what that purpose is.

---

## Before you write code

**Read [SPEC.md](SPEC.md) in full.** It is binding. Field names, file paths and function
signatures in it are contracts — do not rename them, do not "improve" them, do not invent
parallel ones. If something in the spec is wrong, say so in your pull request rather than
silently diverging.

**Know what this project is for.** Two things, and only two:

1. Being a serious bot detector — one that catches headless Chrome on rotating residential
   proxies, not one that greps User-Agent strings.
2. Measuring real time-on-site — visible and engaged time, not "the tab was open".

Everything else is table stakes. **A change that trades accuracy on those two things for
convenience anywhere else will be declined**, however nice the convenience is.

---

## The rules that are not negotiable

### No dependencies

No Composer. No npm. No build step. `git clone` plus `install.sh` has to work on a bare
box with nothing but `php-cli` installed, and it has to work with no network access at
install time.

PHP 8.1+ with `curl`, `json`, `pcre`, `sqlite3` and `mbstring`. Frontend is vanilla JS with
ECharts self-hosted in `public/assets/vendor/` — no CDN, because the panel must work on an
air-gapped box and because the CSP is closed.

If you genuinely need a library, make the case in an issue first. The bar is high.

### Security

This application parses hostile input by definition. Every log line contains
attacker-controlled paths, User-Agents and referers; `collect.php` is a public,
unauthenticated write path.

Read [docs/SECURITY.md](docs/SECURITY.md). The short version:

- **Escape at the sink, in that sink's encoding.** `Security::esc()` for HTML,
  `Security::escJs()` inside `<script>`, `Security::safeUrl()` for `href`/`src`. There is
  exactly one implementation of each; if you are writing `htmlspecialchars()` anywhere
  else, use the helper.
- **Never splice user text into a Solr parameter.** Bound params only
  (`{!edismax v=$uq}` + `uq=`). `rows`/`start` clamped. Field names allowlisted.
- **No raw Solr passthrough.** There is no "proxy this query" endpoint and there will not
  be one.
- **`escapeshellarg()` every argument**, or better, do not shell out at all.
- **Resolve every filesystem path** with `Security::safePath()` against the allowed roots.
- **CSRF token on every state-changing request.**
- **Never add a hardcoded secret**, and never log one.

A pull request that introduces an injection or an escaping gap will be declined regardless
of what else it does.

### Comments

**Every function gets a doc comment saying what it does and why. Every non-obvious line
gets an inline comment.**

This is not bureaucracy. It is a public repository that people will read in order to
decide whether to trust it with their traffic data, and "why" is the part that earns that
trust. Say what a thing does, and say why it is done that way rather than the obvious way.

Look at `src/Tail.php` for the standard: the rotation logic is thirty lines of code and a
hundred lines of explanation, because the explanation is what stops someone "simplifying"
it back into something that silently loses data every night.

### Honesty

- **Never fabricate a metric.** If `engaged_ms` is unknown because no beacon arrived, the
  field is **absent**, not zero. Every aggregate must state which population it covers; an
  unlabelled number is a lie.
- **`bot_score_f` is always accompanied by `bot_reasons_ss`.** A verdict with no reasons is
  a bug, not a rounding error.
- **No invented benchmarks in documentation.** If you need a number you do not have, mark
  it clearly as a placeholder. Do not write "3x faster" unless you measured it and can say
  how.
- **Document the limitations.** The "what this does NOT catch" section of the README and
  the false-positives section of `docs/DETECTION.md` are load-bearing. If your change
  creates a new limitation, write it down there in the same pull request.

### Style

- **4 spaces.** Never tabs.
- **Single quotes in PHP** unless you need interpolation.
- **PSR-12.**
- `declare(strict_types=1);` at the top of every PHP file.
- Namespace `Loghound\`, PSR-4 onto `src/`.
- No AI-assistant attribution in commits, comments or documentation.

---

## Tests

```bash
php tests/run.php                  # everything
php tests/run.php tail             # filter by file or test name
php tests/run.php --list           # what exists
```

**The suite must pass with no network access.** A test that needs an outbound request is
not acceptable; test the pure half of the logic and skip the transport.

### Writing one

`tests/test_<something>.php` returns an array of name to closure:

```php
<?php
return [
    'a hostile line does not crash the parser' => function (): void {
        lh_same(null, $parser->parseLine($fmt, "\x00\x00", 'x', 0));
    },
];
```

The closure passes unless it throws. Assertion helpers (`lh_same`, `lh_true`,
`lh_has_key`, `lh_contains`, `lh_throws`, `lh_tmpdir`, `lh_fixture`, …) live in
`tests/helpers.php` and are already loaded. `lh_skip('reason')` skips a test that cannot
run here.

Files are found by glob — no registration step, no central list to keep in sync.

### What to test

- **Anything that touches the filesystem, against real files.** `src/Tail.php` is tested
  with actual `rename()`, `unlink()` and `truncate()` calls in a temp directory, because
  log rotation *is* filesystem behaviour and a mock would only test the mock.
- **Every scoring rule needs two tests**: one proving it fires when it should, and one
  proving it does **not** fire when it should not. A rule that only has the first test is
  a rule that will misfire in production.
- **Hostile input.** Null bytes, 10 MB lines, invalid UTF-8, `</script>` in a User-Agent,
  `../../etc/passwd` in a path. It arrives in real logs.

### Fixtures

`tests/fixtures/` holds real captured log lines. If you add one:

- **anonymise it** — replace real client IPs with `198.51.100.x` / `203.0.113.x`
  (RFC 5737 documentation ranges), redact tokens and emails;
- **do not anonymise the shape**. Keep the timings, the request ordering and the header
  values, because that is the entire evidentiary value of the file;
- say in the pull request what it demonstrates.

---

## Pull requests

- **One change per pull request.** A bug fix and a refactor in the same diff is two pull
  requests wearing a trench coat, and it will get a slower review.
- **Say what problem you are solving**, not just what you changed. If it is a bug, say how
  you reproduced it.
- **Run `php tests/run.php` before opening it**, and add a test for what you fixed.
- **Update the documentation in the same pull request.** New rule → `docs/DETECTION.md`.
  New config key → `Config::defaults()` *and* wherever it is documented. New field →
  `SPEC.md` §4.
- **Add a `CHANGELOG.md` entry** under Unreleased.
- No AI-assistant attribution anywhere in the commit or the diff.

### Changing a scoring weight

- Say what data you tuned it against, and how much of it.
- **Bump `rule_version`.** It is written onto every session document so a verdict stays
  traceable to the ruleset that produced it. Changing a weight without bumping it makes
  historical scores silently incomparable.
- Both tests: it fires, and it does not misfire.

### Changing the Solr schema

Field names in SPEC.md §4 are a contract. Adding a field is fine; renaming or removing one
needs a discussion first, because it breaks every existing index.

Remember the disk discipline: default to `stored=false` and rely on docValues.
`omitNorms=true` on string fields. Do not reintroduce the stock `_text_` catchall — it
silently doubles the index and nothing uses it.

---

## Good first contributions

- **A log format the detector does not recognise.** Add it to the library in
  `src/LogDetect.php` with a fixture. This is genuinely useful and self-contained.
- **A false positive you hit.** An anonymised fixture plus a note on which rule misfired
  is one of the most valuable things you can send.
- **Documentation that is wrong or unclear.** Especially in `docs/INSTALL.md` — if
  something did not work on your distribution, that is a bug in the docs.
- **A platform the installer mishandles.** It detects rather than assumes, but it has not
  seen every box.

## Things that will be declined

- Adding Composer, npm, or a build step.
- A CDN reference anywhere in the frontend.
- Session replay, keystroke capture, or anything that records page content. See
  `docs/PRIVACY.md` — this is a deliberate boundary, not an oversight.
- A "just proxy this query to Solr" endpoint.
- Cookies in the beacon that are on by default.
- Bot detection based on a User-Agent blocklist alone. That is what everything else does
  and it is why this project exists.

---

## Reporting bugs

Include: what you did, what you expected, what happened, your OS, PHP version and Solr
version, and the relevant output of `loghound-tail --status --human`. If it is a parsing
problem, an anonymised sample line is worth more than any description of it.

**Security issues do not go in the issue tracker** — see
[docs/SECURITY.md](docs/SECURITY.md).

---

## License

By contributing you agree that your contribution is licensed under the MIT License, the
same as the rest of the project.
