# Installing Loghound from a browser

There are two ways to set Loghound up, and they produce the same result:

| | |
|---|---|
| **In a browser** | Point a vhost at `public/`, open the URL, follow three screens. This document. |
| **In a shell** | `bin/loghound-setup` over SSH. See [INSTALL.md](INSTALL.md). |

Neither is a lesser version of the other. Both call the same code in `src/Setup/` to decide
which log files to read, how to grade a format, how to provision the indexes, what a valid
password is and what happens next — so a configuration written by one is indistinguishable
from one written by the other, and you can start in the browser and finish in the shell.

---

## Before you start

You need:

* PHP 8.1 or newer with `curl`, `json`, `pcre`, `sqlite3` and `mbstring`
* a webserver whose document root points at `loghound/public`
* shell access to the machine — the installer asks you to prove it (see [The setup token](#the-setup-token))
* an Opensolr account — Loghound keeps everything it learns in two indexes it provisions there, and does not run without one. It is **free forever to start, no credit card, no expiry date**: [create one](https://opensolr.com/register), [sign in](https://opensolr.com/users/login), or [see what the plans hold](https://opensolr.com/solr-hosting). Have the account email and the API key from **Account** in the control panel ready — the installer asks for both.

`install/install.sh` sets all of this up including a dedicated PHP-FPM pool. Run it with
**`--skip-setup`**: without that flag it hands over to the shell wizard at the end, and a
configuration finished there leaves the browser installer with nothing to do. With it, the
machine is prepared and the final report points you at the URL and at the command that
reads the setup token.

If you would rather do it by hand, `install/apache-vhost.conf.example` and
`install/nginx-vhost.conf.example` are the vhosts, and `install/php-fpm-pool.conf.example`
is the pool.

---

## Opening it

Open the site. Anything that is not ready to serve lands on the installer — no
configuration, half a configuration, or a configuration with no way to sign in. Loghound
never answers a request by printing a configuration error and stopping.

The first screen is a **system check**: one row per requirement, with the exact command
that fixes anything that is not passing, written for the user PHP is actually running as
on this machine. For example, if the service user cannot read your access logs:

```
setfacl -m u:loghound:rx /var/log/apache2
setfacl -m u:loghound:r  /var/log/apache2/example_com_access.log
```

Read that table before continuing. A green install here is the difference between "the
daemon is running" and "the daemon is running and indexing something".

### If you are behind `open_basedir`

The reference PHP-FPM pool (`install/php-fpm-pool.conf.example`) restricts the panel to the
application directory and `/tmp` **plus the three directories this screen depends on**:

```
php_admin_value[open_basedir] = /opt/loghound:/var/log:/etc/apache2:/etc/nginx:/tmp
```

`/var/log` is where your access logs are; `/etc/apache2` and `/etc/nginx` are where the
`CustomLog` and `access_log` directives that name them live, which is how the format is
read exactly rather than guessed. Both are read-only to the pool user by file permissions —
`open_basedir` widens what PHP may *attempt*, not what the operating system will allow.
Drop whichever webserver you do not run, and adjust the first path if you installed
somewhere other than `/opt/loghound`.

If you tightened the pool, or your distribution ships its own, this screen physically
cannot see those directories. The system check says exactly that rather than reporting a
permission problem that does not exist. Either widen `open_basedir` for them, or run
`bin/loghound-setup` in a shell, where the restriction does not apply. The ingest daemon is
never affected either way: it is a CLI process.

---

## The setup token

Before the installer accepts anything that will be written to the configuration, it asks
you to paste a token from a file only this server's administrator can read:

```
sudo cat /opt/loghound/var/install-token
```

This is the same thing Grafana, Matomo and phpMyAdmin do, and it is the only thing standing
between a fresh install and the internet. Until DNS points somewhere else, your URL is
reachable by anyone; without the token, whoever found it first could point Loghound at a
Solr they control and set the password.

The status page itself is readable without the token — you need to be able to SEE a
permission problem in order to go and fix it — but nothing can be saved until it is
entered. Guessing is rate limited, and the token file is deleted the moment setup finishes.

---

## The three steps

Each one writes its answers straight into `config/loghound.php` as you go. There is no
hidden wizard state: reload, change browser, or switch to the shell wizard, and you pick up
exactly where you were.

Setup does not ask how visitor IP addresses are stored or how long hits are kept. A new
installation keeps the full address and deletes hits after 90 days; both are changed under
**Settings → Privacy** in the panel.

### 1. Access logs

Loghound reads your webserver's own log files. It works out the format in this order:

1. **From your webserver configuration.** Parsing `apache2.conf` / `httpd.conf` /
   `nginx.conf` and their includes gives the exact format string, the exact file list and
   the virtual host each log belongs to. Nothing is guessed.
2. **By scoring real lines** against the built-in format library when the configuration is
   not readable — structurally, so a field only counts as an IP address if it parses as one.
3. **By proposing a pattern** generated from your log when nothing matches.

Whichever rung it lands on, you see the file, where the format came from, the confidence
percentage, the token-to-field mapping, and **five real lines rendered as parsed records**.
Read them. If a value is in the wrong column, the format is wrong, and confirming it would
fill your index with nonsense. Nothing is ever ingested with a silently guessed format.

The screen also lists what your format does NOT log and what each gap costs you — the
scoring rules that will stay silent. Plain `combined` works; it just detects less.
`docs/INSTALL.md` has a copy-paste `LogFormat` that closes all of them.

You can also name a file by hand. It must sit inside `allowed_log_roots` (`/var/log` by
default); the browser installer refuses anything outside and will not widen that list for
you, because it is a security control. A custom pattern is checked for catastrophic
backtracking before it is stored, not the first time the daemon meets a hostile line.

### 2. Storage

One answer: Loghound provisions and manages its own two indexes on your Opensolr account.
**An Opensolr account is a hard requirement.**

There used to be a second option — point Loghound at a Solr you already run — and it was
removed. Loghound does not merely read and write these two indexes, it owns them: it creates
them, uploads the configsets under `solr/hits/conf` and `solr/sessions/conf`, reloads the
cores and verifies them, and later reports and trims them against your plan. On a Solr you
administer yourself it has no route to create a core or install a configset and no way to keep
the schema right, so the option promised something the product cannot deliver. If your
configuration still says `solr.mode: custom`, see
[An older configuration on `solr.mode: custom`](#an-older-configuration-on-solrmode-custom).

**Let Opensolr host it.** You do not need to run Solr. The storage step is **two steps, always
in that order**: which account, then which indexes.

#### Step one — which Opensolr account

Enter your account email and API key (in the Opensolr control panel, under Account) and save
them. That is the whole of step one: nothing is asked about indexes and nothing is refused
because of what the account does or does not hold, because you are saying which account to use
and have not yet said anything about where your traffic should land.

Between saving an account and choosing indexes there is a moment where the configuration names
indexes the new account does not hold. That is normal and it is not an error. The screen — and
**Settings → Solr connection**, if you got here from a running installation — says exactly that,
with the list to pick from right beside the sentence. It survives closing the tab.

#### Step two — which indexes

The installer reads your account once and shows you three things before you choose anything:

* **how many indexes the account holds**, and — once it knows — how many your plan allows;
* **the pairs of Loghound indexes already on the account**, which you can join instead of
  creating new ones;
* **anything left over from a setup run that stopped half way**, named individually, because
  it still counts against your plan.

Then it offers **one list**: every pair the account holds, plus one more option meaning *make a
new pair for this site*. You pick one row and confirm. There is no separate "create" form and no
checkbox qualifying a different decision — the list and that last option carry the whole meaning.

A single pair is still something you pick. Loghound does not adopt the only pair on the account
on your behalf.

The same list, the same options in the same order and the same sentences appear in
`bin/loghound-setup` and in **Settings → Solr connection**, because all three render one decision
rather than three descriptions of it.

##### Picking a pair the account already has

One pair of indexes can serve several sites. Every record Loghound writes carries the virtual
host it came from, so a pair collecting traffic from six machines stays separable in the panel
by its **Virtual host** dimension. If you run Loghound on more than one site, this is usually
what you want: two indexes and six hostnames, rather than twelve indexes.

Pairs are listed as pairs — `loghound_<id>_hits` with its matching `loghound_<id>_sessions` —
and are chosen as pairs. Choosing one:

1. confirms the pair is still on the account (the list is an offer, never evidence);
2. reads the connection details;
3. **checks the indexes have the shape this version of Loghound writes**, by comparing their
   live schema against the one in this release, field by field;
4. queries both to prove Loghound can reach and authenticate to them.

**Reusing joins; it never overwrites.** Nothing is cleared, reshaped or reloaded. What this
installation records is added to what is already in there, and the two are told apart by the
hostname on every document.

If the indexes were made by an **older Loghound** and are missing fields this version writes,
the run stops and names the missing fields, having changed nothing. Tick *"add the fields this
version writes"* before you press the button to have them added instead — that only ever adds
fields, and it does not alter or remove a single document already in the index.

An **unmatched half** — a `_hits` with no `_sessions`, or the reverse — is what a setup run
that died between the two creates leaves behind. It is shown as exactly that. It cannot be
joined, because half a pair is not somewhere Loghound can work, and it holds no usable data on
its own; delete it in your Opensolr account when you want the slot back, or leave it. Loghound
will not touch it either way.

##### Picking "make a new pair for this site"

1. Pick one of the regions your account can use — nothing is hardcoded;
2. Loghound checks your plan has room for two more indexes;
3. it creates both with generated names;
4. uploads the schema and solrconfig to each and reloads them;
5. queries each one to prove it can reach and authenticate to it.

Every one of those is a separate step with its own result, so a failure names the step it
failed on. The index names are generated rather than chosen because an Opensolr index name
is unique across the whole platform and permanent once created — a fixed `loghound_hits`
would work for exactly one person.

#### Starting over later

Settings has a **Start over** card, and it starts from zero. It deletes both Opensolr indexes
and every document in them, proves they are gone by reading your account listing again, removes
the configuration with your Opensolr email, API key and region in it, empties `var/`, and brings
you back to these screens with nothing carried across — you provide all of it again, exactly as
now. The only way to keep the data is an Opensolr backup taken **before** you press it, which is
a separately billed feature.

Two things it never touches: your access log files, which are your web server's, and the
`LogFormat` line you added to your own vhost.

It costs a typed `DELETE EVERYTHING` and a code from your authenticator where two-factor is on.
Because you confirmed it while signed in, that browser is carried straight into setup instead of
being asked for the token file. Anyone else still has to read it.

`install/uninstall.sh` is the counterpart for taking Loghound off the machine entirely — the
units, the vhost, the PHP-FPM pool, the command links, the service user and the install tree,
which the card leaves standing because setup is about to run on them.

#### When the plan has no room

Opensolr plans limit how many indexes an account may hold. Loghound checks **before** it
creates anything, and when the plan is full it says so in plain numbers — how many the plan
allows, how many are in use, how many it needs — and withholds the *make a new pair* option
rather than letting you press something that can only fail. Any pair the account already holds
stays on the list, because joining one creates nothing and the limit does not apply to it.

When there is nothing to join **and** no room to create, that is the one dead end, and the screen
says so with the numbers and lists only the ways forward that genuinely exist for your account:
delete an index you no longer need, or move to a larger plan, each linking to your Opensolr
account. The count in the heading is the number of routes actually shown.

The numbers come from Opensolr's own account summary — how many the plan allows, how many
exist, how many more can be created — read fresh every time rather than remembered, because a
plan can change. Asking costs an existing index, since that endpoint is scoped to one core you
own, so an account with no indexes at all has no readable allowance and the screen says so
rather than assuming there is room.

A check is a check, not a promise: another machine can take the last slot in between. If the
*second* index is the one refused, the first is deleted and you are told that nothing was left
behind.

A generated name that is already taken is handled in one of two ways, and which one depends
on **who holds it**:

* **Somebody else holds it.** Both names are abandoned and retried with a fresh installation
  id, because the pair has to share one id to be recognisable as a pair in an account holding
  hundreds of indexes. Anything created during the abandoned attempt is deleted first, so you
  are not billed for an orphan.
* **Your own account already holds it** — which is what a previous attempt of your own leaves
  behind — the index is **reused**, not abandoned. Loghound asks Opensolr which indexes your
  account holds before it decides, and if it cannot get an answer it stops and says so rather
  than guessing, because guessing wrong in that direction leaves you paying for an index
  nothing points at.

Your API key goes into `config/loghound.php` (mode 0640, outside the document root) and
nowhere else. It is never shown again, never placed in a hidden field, never written to a
log, and never included in an error message.

The connection details of the node your indexes landed on — `solr.base_url`,
`solr.http_user`, `solr.http_pass` — are written for you from what Opensolr returns. You never
type them, and there is no form, POST action or environment variable that will accept them from
you. The setup status page has a **Test the connection** button that queries both indexes and
tells you precisely what went wrong if it cannot reach them — "Connection refused to
`fi.solrcluster.com:443`", not "could not connect".

#### An older configuration on `solr.mode: custom`

An installation made before the option was removed still has `solr.mode => 'custom'` in
`config/loghound.php`. That value is now refused, loudly and on purpose:

* `bin/loghound-tail`, `bin/loghound-score` and `bin/loghound-retention` all validate the
  configuration at startup and **refuse to start**, printing what changed, why, and what to
  do about it.
* The panel's Settings page says the same thing at the top of the Solr connection card.

To move: set `solr.mode` to `'opensolr'` and run `bin/loghound-setup`, which will provision
the two indexes on your Opensolr account. **Nothing migrates your existing documents** — the
new indexes start empty, and Loghound backfills only as far as your own log retention reaches.
Your old cores are untouched; delete them when you no longer want them.

### 3. Sign-in

A username and a password of at least ten characters, stored as a hash. Loghound shows
every visitor, page and address on your site, so it is never served without one.

The same screen asks **how** you want to sign in, and it is a real choice with a real
trade-off rather than a default you discover later:

| `auth.mode` | What you get | What it costs |
|---|---|---|
| `basic` | The browser's own password prompt, before it shows anything. Every tool that speaks HTTP signs in the same way, so `curl --user` and monitoring checks work. | The prompt is the browser's and cannot be styled, and there is no way to sign out short of closing the browser. |
| `session` | Loghound's own sign-in page at `?login`, a real session with an idle timeout and an absolute one, and a **Sign out** button at `?logout` that ends it on the server. | It only works in a browser. `curl` and scripts cannot sign in to it, so a monitoring check against the panel has to move to Basic or be dropped. |

Failed attempts are rate limited per address in **both** modes, by the same ledger: too many
and that address is locked out for a window, answered with `429` and a `Retry-After`. In
session mode the sign-in form also refuses to say which half was wrong, so it cannot be used
to enumerate usernames.

You can change the mode later under Settings without setting the password again.

The same commands are kept in the panel under **Settings → Finish setting up**, together
with whether each one has actually taken effect, so nothing here is lost when this screen
goes away:

```
sudo systemctl enable --now loghound-tail.service loghound-score.timer loghound-retention.timer
```

`enable --now` starts the service and both timers immediately and brings them back after a
reboot. The panel reports whether they are running — it reads the status document the
tailer writes about itself — but it cannot see whether they are enabled at boot, because
Loghound executes no processes.

Finishing takes you to the dashboard, which then asks you to sign in for the first time with
the username and password you just chose — through your browser's own prompt in `basic`
mode, or through Loghound's sign-in page in `session` mode.

---

## Long operations

Provisioning two Opensolr indexes takes tens of seconds, and PHP-FPM will not hold a request
open that long. So the slow parts — credential checks, index creation, configset uploads,
connectivity tests and log detection — run as **jobs**: a list of small named steps whose
state lives in `var/setup/`. The browser advances them a budget at a time and polls for
progress, so you see which step is running, how long it has been going and what it is doing
right now.

Refreshing mid-provision reattaches to the running job rather than starting a second one.
Two indexes are never created because somebody double-clicked.

### What "Try again" actually does

It does **not** resume the failed job. A job that has failed is no longer running, so there
is nothing to reattach to: the button starts a **new** job, and every step runs again from
the top. That is safe because each step is idempotent against work an earlier attempt
already did, and the two that could have cost you something are explicit about it:

* **Index creation** finds the name already taken — the installation id is stored, so the
  retry derives the same two names — asks Opensolr whether *your* account is the one holding
  it, and reuses it. The step says so: "already exists from an earlier attempt — reusing it".
  A retry after a failed provision therefore does not leave the first attempt's indexes
  behind for you to find on your next invoice.
* **Configset upload** re-uploads both files and reloads the index, which is the same
  operation whether or not it landed the first time.

The rest only read: the credential check lists regions, the connection step re-reads where
the indexes live, and the verification steps query. So what you see on a retry is every step
running again and most of them saying "already done" — not a shorter list.

If Opensolr cannot be reached at the moment the retry needs to ask who owns a name, the step
stops with that as the reason and changes nothing. That is deliberate: the alternative is
guessing, and guessing wrong there is what abandons an index you are paying for.

The installer needs JavaScript for these screens, and says so. The shell wizard runs the
identical steps with no JavaScript involved.

---

## When the installer disappears

The moment `config/loghound.php` exists, carries a username and a password hash, and names
both indexes, every installer route is dead and the panel serves instead. There is no flag,
no query parameter and no "re-run setup" button that gets past that check.

Those three conditions are the whole of it, and the narrowness is deliberate. The check
runs *before* authentication, so anything that makes it true hands an unauthenticated
visitor the installer — which means it must depend only on facts that mean "setup never
finished", never on whether the configuration is otherwise perfect. It used to ask
`Config::validate()` instead, and `validate()` reports an error for a log directory it
cannot resolve — the normal state of a panel process under `open_basedir`. A correctly
installed instance therefore looked unconfigured forever: the status page disclosed the
environment, the paths and the index names to anyone who asked, and re-minted a live setup
token on a machine where it had already been destroyed.

Configuration problems that are *not* "setup never finished" — an unreadable log directory,
a missing beacon secret — show up as a warning banner inside the panel, with a link to
Settings. That is the right severity for them. The check does not probe Solr either: a
momentary outage must not bounce you out of your own dashboard and re-open the installer.

To change something afterwards:

* **Settings** in the panel covers log sources, privacy, scoring weights and the beacon.
* `bin/loghound-setup` re-runs the whole wizard; every prompt defaults to the current value
  and an existing secret is kept unless you ask for a new one.

Deleting `config/loghound.php` brings the installer back, with a fresh setup token. That is
a deliberate escape hatch, and it needs shell access twice over — once to delete the file
and once to read the new token.

---

## What it does with your answers

| Screen | Configuration it writes |
|---|---|
| Access logs | `sources`, and `allowed_log_roots` when you explicitly agree to widen it |
| Storage | `solr.mode` (always `opensolr`), `solr.install_id`, `solr.hits_core`, `solr.sessions_core`, `solr.base_url`, `solr.http_user`, `solr.http_pass`, `opensolr.email`, `opensolr.api_key`, `opensolr.region` |
| Sign-in | `auth.mode`, `auth.user`, `auth.password_hash`, `base_url`, and the two generated secrets `beacon.secret` and `privacy.ip_salt` |

`privacy.ip_mode` and `privacy.retention_days` are not written by either installer. They keep
their defaults — the full address, 90 days — until they are changed under **Settings →
Privacy**.

`config/loghound.example.php` documents every setting, including the ones neither installer
asks about.

---

## Security summary

* The installer is unreachable once a valid configuration exists.
* Nothing is written until the setup token — a 0600 file — has been pasted.
* Every state-changing request carries a CSRF token; no privileged action happens on a GET.
* Steps cannot be reached out of order by guessing a URL.
* No secret is rendered anywhere: not the API key, the beacon signing key, the address salt
  or the password. Where it matters that one is set, the screen says "stored".
* Sample log lines are attacker-controlled by definition and are escaped on the way out;
  the page's Content-Security-Policy is `script-src 'self'` with no inline scripts.
* A hand-typed log path is resolved with `realpath()` and refused unless it is inside
  `allowed_log_roots`; a custom pattern is refused unless it compiles and runs fast.

`docs/SECURITY.md` covers the rest of the application.
