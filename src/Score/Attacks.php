<?php
/**
 * Loghound — hostile-request detection (the vocabulary behind the Attacks view).
 *
 * ---------------------------------------------------------------------------------------
 * WHAT THIS IS, AND WHAT IT IS NOT
 * ---------------------------------------------------------------------------------------
 * This file reads a request that has ALREADY BEEN SERVED and says what it looks like it was
 * trying to do. It is not a WAF. It sits nowhere near the request path, it blocks nothing,
 * it cannot block anything, and no label it produces may ever be worded as though it had.
 * Loghound reads an access log after the fact; the server had already answered by the time
 * these bytes reached disk.
 *
 * That is why THE STATUS CODE IS THE WHOLE POINT and not a column. A traversal attempt
 * answered with 404 is noise — it is what a webserver is supposed to do, and any site on the
 * public internet collects thousands a day. The same attempt answered with 200 is an
 * incident, because something served a body. Every card in Panel\Attacks is ordered by what
 * the server ANSWERED and not by how alarming the request string looks, which is the opposite
 * of what a list-of-scary-strings tool does.
 *
 * And the other direction has to be stated just as plainly, because it is the failure mode
 * that would make this untrustworthy: A 200 IS NOT PROOF OF COMPROMISE. A site whose error
 * page is served with a 200 status — a SPA shell, a CMS catch-all route, a misconfigured
 * ErrorDocument — looks identical in a log to one that handed over `/etc/passwd`. The panel
 * says "answered with a 200" and never "disclosed"; the operator fetches the URL and decides.
 *
 * ---------------------------------------------------------------------------------------
 * WHY THIS RUNS AT INGEST AND NOT AT QUERY TIME
 * ---------------------------------------------------------------------------------------
 * Three facts decide it, and none of them is a preference:
 *
 *  1. `query_s` IS NOT INDEXED. The hits schema stores the query string and deliberately
 *     gives it no index and no docValues — it is unbounded attacker-controlled text with a
 *     near-unique value per request, and a term dictionary over it would be the size of the
 *     corpus. So SQL, template and command-injection probes, which live almost entirely in
 *     the query string, CANNOT be found by any Solr query at all. They can only be seen by
 *     the code that is holding the request while it parses it, or by reading every stored
 *     document back — which is the thing this product refuses to do at dashboard speed.
 *  2. `path_s` is a `string` field with no analysis. Finding `../` inside it at query time
 *     means a LEADING wildcard across a term dictionary of every distinct URL the site has
 *     ever served. That is the single most expensive query shape Solr has.
 *  3. The work is free where it is done. Parser::normalize() already has the decoded path and
 *     the query string in local variables; matching them costs a bounded set of substring
 *     tests on a string that is already in a register.
 *
 * So the codes are computed once, at ingest, and written to `hit_flags_ss` — a field the
 * schema has carried since the beginning for exactly this ("signal codes fired by this single
 * hit") and which nothing had ever written. Faceting that field against `status_i` in one
 * Solr request is then the whole view.
 *
 * ---------------------------------------------------------------------------------------
 * THREE STATES, AND THE FIELD THAT MAKES THEM DISTINGUISHABLE
 * ---------------------------------------------------------------------------------------
 * `hit_flags_ss` absent means two different things — "evaluated, nothing matched" and "never
 * evaluated, because this document was written before the detector existed" — and a view that
 * cannot tell them apart reports a quiet period that is really a deployment gap.
 *
 * So every evaluated document also carries `hit_rules_i`, the version of THIS table that
 * judged it:
 *
 *   `hit_rules_i` absent           never evaluated. Not "clean".
 *   present, no `hit_flags_ss`     evaluated under that version; nothing matched.
 *   present, with `hit_flags_ss`   these patterns matched.
 *
 * Panel\Attacks states the covered period from that field and refuses to imply anything about
 * documents outside it. Bump RULE_VERSION whenever a pattern changes, so an operator can see
 * which ruleset produced a historical finding — the same contract `rule_version_i` has on the
 * session document.
 *
 * ---------------------------------------------------------------------------------------
 * FALSE POSITIVES ARE A FIRST-CLASS CONCERN
 * ---------------------------------------------------------------------------------------
 * This product's stated position on bot detection is that a detector that guesses is worse
 * than no detector, because people believe it. A security page that cries wolf is the same
 * defect with higher stakes. Every rule below therefore carries THREE sentences and not one:
 * what it matches exactly, what it is known to MISS, and what it is known to OVER-REPORT.
 * docs/ATTACKS.md renders all three, and the view links to it from the page.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Score;

final class Attacks
{
    /**
     * The version of this rule table.
     *
     * Written to `hit_rules_i` on every evaluated hit and to the session that folds it up.
     * Bump it whenever a pattern is added, removed or changed, so a finding can be read
     * against the ruleset that produced it rather than against the one installed today.
     */
    public const RULE_VERSION = 1;

    /**
     * How much of the request surface is examined.
     *
     * A bound, not a tuning knob. This runs once per log line on a machine that is also
     * serving traffic, and a hostile client can put a megabyte in a query string for the cost
     * of one request. Every pattern this table looks for is short and appears early; nothing
     * is lost by refusing to scan past 4 KB, and an unbounded scan would turn one crafted
     * request into measurable ingest cost.
     */
    public const MAX_SURFACE = 4096;

    /**
     * How many decoding rounds the surface goes through.
     *
     * `%252e%252e%252f` is `%2e%2e%2f` is `../`: double encoding is the oldest way past a
     * filter that decodes once. Two rounds catch it. A third buys nothing real and gives a
     * crafted string a way to cost more, and a decoder that loops until stable is a decoder
     * an attacker chooses the runtime of.
     */
    private const DECODE_ROUNDS = 2;

    /**
     * Severity words, in the order the panel sorts them.
     *
     * The same four Score\Rules uses, deliberately: an operator reading both pages should not
     * have to learn two vocabularies for the same idea.
     *
     * @var array<int,string>
     */
    public const SEVERITIES = ['high', 'med', 'low', 'info'];

    /**
     * THE DETECTION VOCABULARY. One row per pattern; the panel shows the label, never the slug.
     *
     * Each row carries:
     *   `label`     what a person reads. The slug never reaches a screen.
     *   `family`    the group the view bands rows into: disclosure, injection, exploit,
     *               credential, recon, impersonation.
     *   `severity`  how much a MATCH is worth before the status code is known. It is not a
     *               verdict: severity high answered with 404 still ranks below severity med
     *               answered with 200, because what the server did outranks what was tried.
     *   `what`      exactly what the pattern matches. One sentence, no hedging.
     *   `misses`    what it is known NOT to catch. Stated because a security page that implies
     *               completeness is worse than one that admits its edges.
     *   `over`      what it is known to over-report, and therefore what an operator should
     *               check before acting on a row.
     *
     * @var array<string,array{label:string,family:string,severity:string,what:string,misses:string,over:string}>
     */
    public const RULES = [
        'atk_traversal' => [
            'label'    => 'Path traversal',
            'family'   => 'disclosure',
            'severity' => 'high',
            'what'     => 'A `../` or `..\\` sequence in the path or the query string, in any encoding: '
                . 'raw, percent-encoded (%2e%2e%2f), double percent-encoded (%252e), overlong UTF-8 '
                . '(%c0%ae) and the backslash forms Windows accepts.',
            'misses'   => 'Traversal that reaches its target without a dot-dot segment at all — an absolute '
                . 'path passed to a file parameter, a symlink the application follows, a path the '
                . 'application itself builds from an id. Those look like ordinary requests in a log and '
                . 'no log-reading tool can see them.',
            'over'     => 'Legitimate URLs that contain a literal `..`: some documentation sites and '
                . 'package registries publish paths with version ranges in them, and a few JavaScript '
                . 'bundlers emit source-map URLs containing `../`. Check whether the path is one your '
                . 'own site publishes before treating it as an attempt.',
        ],

        'atk_sensitive_file' => [
            'label'    => 'Sensitive file request',
            'family'   => 'disclosure',
            'severity' => 'high',
            'what'     => 'A request whose target names a file that holds credentials or process state: '
                . '`.env`, `/proc/self/environ`, `.git/config`, `.git/HEAD`, `wp-config.php`, '
                . '`.aws/credentials`, `.ssh/id_rsa`, `.htpasswd`, `.npmrc`, `.dockercfg`, '
                . '`docker-compose.yml`, `web.config` and their close relatives.',
            'misses'   => 'A secret in a file this list does not name — an application-specific config '
                . 'file, a credentials file under a custom name. The list is the well-known set that '
                . 'scanners try, not an inventory of your secrets.',
            'over'     => 'A documentation site that legitimately serves a page ABOUT `.env` files, and '
                . 'any site with a real `.well-known` style path containing one of these words. A '
                . 'developer fetching their own `.env` over HTTP will also appear here, which is worth '
                . 'knowing either way.',
        ],

        'atk_backup_file' => [
            'label'    => 'Backup or dump file',
            'family'   => 'disclosure',
            'severity' => 'med',
            'what'     => 'A request for a file whose extension marks it as a backup, an editor leftover '
                . 'or a database dump: `.sql`, `.sql.gz`, `.bak`, `.old`, `.orig`, `.save`, `.swp`, '
                . '`.swo`, a trailing `~`, or `.tar.gz` / `.zip` / `.7z` / `.rar` named after the site '
                . 'or a date.',
            'misses'   => 'A backup left under a name that reveals nothing — `a.gz`, an eight-character '
                . 'random name. Guessing those is what makes this rule a list rather than a pattern.',
            'over'     => 'Sites that legitimately publish archives: a downloads directory, a release '
                . 'page, a project that ships `.sql` schema files as documentation. If the 200s on this '
                . 'row are all one path under `/downloads/`, that is your own site working.',
        ],

        'atk_sql_injection' => [
            'label'    => 'SQL injection probe',
            'family'   => 'injection',
            'severity' => 'high',
            'what'     => 'SQL grammar in a place a value belongs: `union select`, `or 1=1`, `\' or \'\'=\'`, '
                . '`information_schema`, `sleep(`, `benchmark(`, `waitfor delay`, `pg_sleep(`, '
                . '`xp_cmdshell`, `concat(0x`, and the MySQL executable-comment form `/*!`.',
            'misses'   => 'Blind injection carried in a value that contains no SQL keyword at all — a '
                . 'single quote and an arithmetic expression, a time-based probe expressed in the '
                . 'application\'s own syntax. It also cannot see anything in a POST BODY, which is '
                . 'where most real injection goes; an access log records the request line, never the body.',
            'over'     => 'Any site whose users legitimately type SQL, or search for it: a documentation '
                . 'site, a forum for developers, a query builder, an analytics tool with a query box. '
                . 'On those, this rule is mostly false and should be read with the response code and '
                . 'the referrer beside it.',
        ],

        'atk_command_injection' => [
            'label'    => 'Command injection probe',
            'family'   => 'injection',
            'severity' => 'high',
            'what'     => 'Shell metacharacters combined with a shell verb: `$(`, a backtick pair, '
                . '`;cat `, `|id`, `&&whoami`, `/bin/sh`, `/bin/bash`, `nc -e`, `wget http`, `curl http` '
                . 'and `%0a` followed by a command word.',
            'misses'   => 'Injection into a language runtime rather than a shell, and anything in a POST '
                . 'body. A payload that uses only the target application\'s own function names will not '
                . 'contain a shell verb and will not match.',
            'over'     => 'URLs that legitimately contain a `$(` — a few JavaScript bundles and template '
                . 'previews do — and any site where a user can search for shell syntax. The `wget`/`curl` '
                . 'halves over-report on documentation and paste sites.',
        ],

        'atk_template_injection' => [
            'label'    => 'Template or expression injection',
            'family'   => 'injection',
            'severity' => 'high',
            'what'     => 'A server-side template or expression-language construct in a parameter: '
                . '`${...}`, `{{...}}`, `#{...}`, `<%= %>`, `T(java.lang`, `__import__`, `getRuntime`, '
                . 'and their percent-encoded forms.',
            'misses'   => 'Template injection that uses only characters the application treats as '
                . 'ordinary — an engine with a custom delimiter, or a payload assembled across several '
                . 'parameters. It also cannot see a POST body.',
            'over'     => 'Front ends that put an un-rendered template into a URL, which happens more '
                . 'often than it should: a broken share link, a mail client rewriting a `{{name}}` '
                . 'placeholder, a preview URL from a page builder. Check whether the `{{` came from '
                . 'your own site before reading it as a probe.',
        ],

        'atk_log4shell' => [
            'label'    => 'JNDI lookup probe',
            'family'   => 'injection',
            'severity' => 'high',
            'what'     => 'A `${jndi:` lookup, or `ldap://`, `rmi://`, `dns://`, `iiop://` or `corba://` '
                . 'appearing inside a `${...}` construct — the Log4Shell family, which is still one of '
                . 'the most-attempted patterns on the public internet.',
            'misses'   => 'The obfuscated forms that split the word across lookups (`${${lower:j}ndi:`) '
                . 'are caught by the `${jndi` half only when the letters survive decoding; a payload '
                . 'that nests enough lookups will not match. It cannot see headers at all, and most '
                . 'Log4Shell payloads arrive in a header rather than a URL.',
            'over'     => 'Almost nothing. This is the highest-precision pattern in the table: no '
                . 'ordinary application puts `${jndi:` in a URL. A match here is worth looking at even '
                . 'with a 404 beside it, because it tells you your address is on somebody\'s list.',
        ],

        'atk_ssrf' => [
            'label'    => 'SSRF or metadata probe',
            'family'   => 'injection',
            'severity' => 'high',
            'what'     => 'A parameter carrying an address that only makes sense if the SERVER is meant '
                . 'to fetch it: `169.254.169.254`, `metadata.google.internal`, `/latest/meta-data`, '
                . '`127.0.0.1`, `localhost`, `[::1]`, or a `file://`, `gopher://` or `dict://` scheme.',
            'misses'   => 'An SSRF target that is an ordinary public hostname — an attacker\'s own '
                . 'collector, a DNS-rebinding name. Those are indistinguishable from a legitimate URL '
                . 'parameter in a log.',
            'over'     => 'Development and preview traffic: a staging front end configured with '
                . '`http://localhost:3000` in a redirect parameter, an OAuth callback to `127.0.0.1`, '
                . 'a health-check URL. If the matching requests all come from your own address space, '
                . 'that is what this is.',
        ],

        'atk_known_exploit' => [
            'label'    => 'Known exploit path',
            'family'   => 'exploit',
            'severity' => 'high',
            'what'     => 'The request target is one of the recurring CVE probe paths every public server '
                . 'sees: the PHPUnit `eval-stdin.php` RCE, Spring Boot `/actuator/gateway/routes`, '
                . 'Laravel `/_ignition/execute-solution`, `/HNAP1`, `/boaform/admin/formLogin`, '
                . '`/cgi-bin/luci`, Liferay `/api/jsonws/invoke`, ThinkPHP `/index.php?s=/Index/\\think`, '
                . 'Exchange `/autodiscover/autodiscover.json`, `/console/login/LoginForm.jsp` and their '
                . 'kin.',
            'misses'   => 'Every CVE published after this table was written, and every exploit whose '
                . 'entry point is an ordinary application URL rather than a distinctive path. A list of '
                . 'known paths is by construction always behind.',
            'over'     => 'Very little, with one real exception: if you actually RUN the software being '
                . 'probed, the same path is a legitimate request from your own tooling. A Solr admin '
                . 'endpoint hit from your own monitoring is the obvious case.',
        ],

        'atk_admin_probe' => [
            'label'    => 'Admin panel probe',
            'family'   => 'recon',
            'severity' => 'low',
            'what'     => 'A request for a well-known administration entry point the site does not '
                . 'necessarily run: `/wp-admin`, `/wp-login.php`, `/administrator/`, `/phpmyadmin`, '
                . '`/pma/`, `/adminer.php`, `/manager/html`, `/server-status`, `/xmlrpc.php`, '
                . '`/solr/#/` and similar.',
            'misses'   => 'An admin panel mounted on a custom path, which is the whole point of mounting '
                . 'it on one.',
            'over'     => 'Enormously, and deliberately so — this is the loudest and least alarming row '
                . 'in the table. If you run WordPress, every `/wp-login.php` from your own editors lands '
                . 'here. It is severity LOW for that reason and is worth reading only through the status '
                . 'column: `/phpmyadmin` answered 404 ten thousand times is the background radiation of '
                . 'the internet, and the same path answered 200 is a finding.',
        ],

        'atk_installer_probe' => [
            'label'    => 'Installer probe',
            'family'   => 'recon',
            'severity' => 'med',
            'what'     => 'A request for a setup or installation script that should not survive '
                . 'deployment: `/install.php`, `/setup.php`, `/wp-admin/install.php`, '
                . '`/setup-config.php`, `/upgrade.php`, `/installer/`, `/_install`.',
            'misses'   => 'A framework whose installer lives under an application-specific route.',
            'over'     => 'A site that is genuinely being installed or upgraded right now. Read the '
                . 'timestamps: a burst from one address during your own deployment window is you.',
        ],

        'atk_wellknown_abuse' => [
            'label'    => 'Unregistered /.well-known path',
            'family'   => 'recon',
            'severity' => 'med',
            'what'     => 'A request under `/.well-known/` for a suffix that is not one of the ordinary '
                . 'registered ones (acme-challenge, security.txt, change-password, '
                . 'apple-app-site-association, assetlinks.json, openid-configuration, oauth-authorization-server, '
                . 'host-meta, webfinger, nodeinfo, traffic-advice, dnt-policy.txt, matrix, discord, '
                . 'gpc.json). That directory is world-readable and frequently world-WRITABLE because '
                . 'ACME needs it to be, which makes it the favourite place to leave a web shell.',
            'misses'   => 'A shell dropped anywhere else, and a shell dropped under a name that '
                . 'impersonates a registered suffix.',
            'over'     => 'Any `.well-known` suffix registered after this list was written, and any '
                . 'private convention your own stack uses under that prefix. A row here answered 200 by '
                . 'a path YOU recognise is a rule that needs a new entry, not an incident.',
        ],

        'atk_login_probe' => [
            'label'    => 'Login endpoint request',
            'family'   => 'credential',
            'severity' => 'info',
            'what'     => 'A POST (or a PUT) to a path shaped like a sign-in endpoint: `/login`, '
                . '`/signin`, `/user/login`, `/wp-login.php`, `/admin/login`, `/auth`, `/api/login`, '
                . '`/oauth/token`, `/session`, `/xmlrpc.php`.',
            'misses'   => 'A credential attack against an endpoint on a custom path, and a credential '
                . 'STUFFING run that spreads a handful of attempts across thousands of addresses so no '
                . 'single session looks busy.',
            'over'     => 'By construction: ONE of these is a person signing in, and this code marks '
                . 'every one of them. It is severity INFO and it is the only row in the table whose '
                . 'meaning is entirely in the COUNT — the view groups it by session and by address, so '
                . 'the finding is "four hundred POSTs to /login from one address, 401 every time", never '
                . 'the single request. Read this row on its own and you will read your own users.',
        ],

        'atk_xss' => [
            'label'    => 'XSS payload',
            'family'   => 'injection',
            'severity' => 'med',
            'what'     => 'Script-injection syntax in a parameter or a path: `<script`, `javascript:`, '
                . '`onerror=`, `onload=`, `onmouseover=`, `<svg`, `<iframe`, `document.cookie`, '
                . '`alert(1)` and `String.fromCharCode(`, in raw or percent-encoded form.',
            'misses'   => 'Payloads that carry no angle bracket and no `on…=` handler — DOM-based XSS '
                . 'delivered through a fragment, which never reaches the server at all and therefore '
                . 'never reaches a log. Anything in a POST body.',
            'over'     => 'Reflected XSS testing is what security researchers do all day, so a bug-bounty '
                . 'programme fills this row legitimately. So does any site whose search box gets '
                . 'pasted-in HTML. The status code is again the separator: an XSS string answered 200 '
                . 'means the string came back in a page, which is worth ten minutes with view-source.',
        ],

        'atk_scanner_ua' => [
            'label'    => 'Scanner User-Agent',
            'family'   => 'recon',
            'severity' => 'med',
            'what'     => 'The User-Agent names a security scanner or fuzzer outright: sqlmap, nikto, '
                . 'nmap, masscan, zgrab, nuclei, wpscan, acunetix, netsparker, dirbuster, gobuster, '
                . 'feroxbuster, ffuf, wfuzz, arachni, openvas, qualys, zaproxy, burp, commix, whatweb, '
                . 'joomscan, droopescan, metasploit, hydra, havij, xray.',
            'misses'   => 'Every scanner run with `--user-agent "Mozilla/5.0 …"`, which is the default '
                . 'advice in every tutorial. A serious operator changes it; this rule catches the ones '
                . 'who did not, plus the scanners that announce themselves on purpose.',
            'over'     => 'Your own security testing, and any commercial scanning service you pay for. '
                . 'Those are the same requests from the same tools, and there is nothing in a log that '
                . 'distinguishes an authorised scan from an unauthorised one except the address it came '
                . 'from.',
        ],

        'atk_method_abuse' => [
            'label'    => 'Unexpected HTTP method',
            'family'   => 'recon',
            'severity' => 'low',
            'what'     => 'A request method that an ordinary website has no use for: TRACE, TRACK, DEBUG, '
                . 'CONNECT, or the WebDAV verbs PROPFIND, PROPPATCH, MKCOL, MOVE, COPY, LOCK, UNLOCK and '
                . 'SEARCH.',
            'misses'   => 'Nothing within its own definition — the method is recorded verbatim, so this '
                . 'rule is exact. It says nothing about what the request was FOR.',
            'over'     => 'If you actually serve WebDAV — a CalDAV or CardDAV endpoint, a Nextcloud '
                . 'install, an SVN repository over HTTP — then PROPFIND is your application working '
                . 'normally and this row will be enormous and meaningless. Filter it out by path if so.',
        ],

        'atk_proxy_probe' => [
            'label'    => 'Open-proxy probe',
            'family'   => 'recon',
            'severity' => 'med',
            'what'     => 'The request line carries an ABSOLUTE URI — `GET http://example.com/ HTTP/1.1` '
                . '— naming a host that is not one this server answers for, which is how a client asks a '
                . 'proxy to fetch something. A normal browser sends an origin-form path.',
            'misses'   => 'A proxy probe sent in origin form with only a forged `Host:` header, which is '
                . 'indistinguishable from ordinary virtual-host traffic in most log formats.',
            'over'     => 'If this machine IS a forward proxy, every request through it is absolute-form '
                . 'and this row is the whole log. It also fires on some cache-poisoning research traffic '
                . 'and on badly configured monitoring that was pointed at the wrong origin.',
        ],

        'atk_crawler_impersonation' => [
            'label'    => 'Crawler impersonation',
            'family'   => 'impersonation',
            'severity' => 'high',
            'what'     => 'A User-Agent claiming a major named search or AI crawler, arriving from an '
                . 'address whose reverse DNS is a GENERAL-PURPOSE CLOUD TENANT name — '
                . '`*.bc.googleusercontent.com`, `*.compute.amazonaws.com`, `*.cloudapp.azure.com`, '
                . '`*.your-server.de`, `*.ovh.net`, `*.digitalocean.com`, `*.vultr.com`, '
                . '`*.linodeusercontent.com`, `*.contabo.net` and their kin. Every crawler on that list '
                . 'runs on its operator\'s own infrastructure and publishes reverse DNS to prove it; '
                . 'Googlebot answers from `*.googlebot.com`, never from `*.googleusercontent.com`, which '
                . 'is where a rented VM lives.',
            'misses'   => 'An impersonator on an address with NO reverse DNS at all, or on a residential '
                . 'proxy, or on a cloud this list does not name. It also misses the case the scorer '
                . 'already owns: a crawler whose operator publishes verifiable reverse DNS and failed '
                . 'the check fires `rdns_claim_failed` on the session instead, and the Attacks view '
                . 'counts both together.',
            'over'     => 'A legitimate crawler that genuinely runs on rented cloud capacity and has set '
                . 'its reverse DNS to the provider default. None of the operators on the claimed-name '
                . 'list does that today, which is what makes the rule safe — but if one starts, this '
                . 'rule is where it will show up as a wrong answer.',
        ],
    ];

    /**
     * Reverse-DNS suffixes that mean "a machine somebody rented", not "a crawler operator".
     *
     * The distinction the impersonation rule turns on. `googlebot.com` is Google's crawler
     * fleet; `googleusercontent.com` is a Compute Engine customer. `amazonaws.com` under
     * `compute.` is an EC2 tenant. A named crawler never answers from one of these.
     *
     * @var array<int,string>
     */
    private const TENANT_RDNS = [
        '.bc.googleusercontent.com',
        '.googleusercontent.com',
        '.compute.amazonaws.com',
        '.compute-1.amazonaws.com',
        '.cloudapp.azure.com',
        '.cloudapp.net',
        '.your-server.de',
        '.hetzner.com',
        '.ovh.net',
        '.ovh.ca',
        '.digitalocean.com',
        '.vultr.com',
        '.vultrusercontent.com',
        '.linodeusercontent.com',
        '.members.linode.com',
        '.contabo.net',
        '.contabo.host',
        '.scaleway.com',
        '.upcloud.host',
        '.oraclevcn.com',
        '.oracleclouduser.com',
        '.clients.your-server.de',
    ];

    /**
     * Declared-crawler categories whose operators run their own infrastructure.
     *
     * The impersonation rule fires only for these. A UA declaring "MyCompanyBot/1.0" from an
     * EC2 instance is somebody's perfectly ordinary integration, and flagging it would be the
     * crying-wolf failure this file exists to avoid. `search` and `ai` are the two categories
     * whose members — Googlebot, bingbot, GPTBot, ClaudeBot — all publish their own address
     * space and none of which rents general-purpose cloud capacity.
     *
     * @var array<int,string>
     */
    private const IMPERSONABLE_CATEGORIES = ['search', 'ai'];

    /**
     * Substrings that mean path traversal, tested against the decoded surface.
     *
     * @var array<int,string>
     */
    private const TRAVERSAL = ['../', '..\\', '/..', '..;/'];

    /**
     * Sensitive file names, tested against the decoded surface.
     *
     * @var array<int,string>
     */
    private const SENSITIVE = [
        '/proc/self/environ', '/proc/self/cmdline', '/etc/passwd', '/etc/shadow',
        '.env', '.env.local', '.env.production', '.env.bak',
        '.git/config', '.git/head', '.git/index', '.gitconfig',
        '.svn/entries', '.hg/store',
        'wp-config.php', 'configuration.php', 'settings.py', 'local_settings.py',
        '.aws/credentials', '.aws/config', '.ssh/id_rsa', '.ssh/id_dsa', '.ssh/authorized_keys',
        '.htpasswd', '.netrc', '.npmrc', '.pypirc', '.dockercfg', '.docker/config.json',
        'docker-compose.yml', 'docker-compose.yaml', 'web.config', '.bash_history',
        'id_rsa', 'credentials.json', 'secrets.yml', 'secrets.yaml', 'appsettings.json',
        'phpinfo.php', '/.aws/', '/.ssh/',
    ];

    /**
     * Backup and dump markers, tested against the decoded surface.
     *
     * @var array<int,string>
     */
    private const BACKUP = [
        '.sql', '.sql.gz', '.sql.zip', '.dump', '.bak', '.bak.php', '.old', '.orig', '.save',
        '.swp', '.swo', '.tmp.php', '.php~', '.inc.bak', '.backup', '.tar.gz', '.tar.bz2',
        '.7z', '.rar', 'backup.zip', 'db.zip', 'www.zip', 'site.zip', 'dump.zip',
    ];

    /**
     * SQL grammar markers, tested against the decoded surface.
     *
     * @var array<int,string>
     */
    private const SQLI = [
        'union select', 'union all select', 'information_schema', 'group_concat(',
        'concat(0x', 'sleep(', 'benchmark(', 'pg_sleep(', 'waitfor delay', 'xp_cmdshell',
        'load_file(', 'into outfile', 'into dumpfile', '/*!', 'or 1=1', 'or 1 = 1',
        "' or '", '" or "', 'and 1=1', 'and 1=2', '@@version', 'extractvalue(',
        'updatexml(', 'having 1=1', 'order by 1--', 'select * from',
        'sp_executesql', 'declare @', 'utl_inaddr', 'dbms_pipe.receive_message',
    ];

    /**
     * Shell metacharacters and verbs, tested against the decoded surface.
     *
     * @var array<int,string>
     */
    private const CMDI = [
        '$(', ';cat ', ';ls ', ';id', '|id', '|cat ', '&&whoami', ';whoami', '`id`', '`whoami`',
        '/bin/sh', '/bin/bash', 'bin/busybox', 'nc -e', 'ncat ', 'wget http', 'curl http',
        'chmod 777', 'rm -rf', 'python -c', 'perl -e', '>/dev/tcp/',
    ];

    /**
     * Template and expression-language constructs, tested against the decoded surface.
     *
     * @var array<int,string>
     */
    private const TEMPLATE = [
        '{{', '#{', '<%=', '<%-', 't(java.lang', '__import__', 'getruntime', 'freemarker',
        'org.springframework', '#set(', '${@', '${7*7}',
    ];

    /**
     * JNDI and remote-lookup schemes, tested against the decoded surface.
     *
     * @var array<int,string>
     */
    private const JNDI = ['${jndi:', '${ctx:', 'jndi:ldap', 'jndi:rmi', 'jndi:dns', 'jndi:iiop'];

    /**
     * Addresses and schemes that only make sense if the SERVER fetches them.
     *
     * @var array<int,string>
     */
    private const SSRF = [
        '169.254.169.254', 'metadata.google.internal', '/latest/meta-data', '/computemetadata/',
        'file://', 'gopher://', 'dict://', 'php://', 'expect://',
        '://127.0.0.1', '://localhost', '://[::1]', '://0.0.0.0', '://169.254.',
    ];

    /**
     * Script-injection syntax, tested against the decoded surface.
     *
     * @var array<int,string>
     */
    private const XSS = [
        '<script', '</script', 'javascript:', 'onerror=', 'onload=', 'onmouseover=', 'onfocus=',
        '<svg', '<iframe', '<img src=x', 'document.cookie', 'string.fromcharcode(',
        'alert(1)', 'alert(document', 'prompt(1)', 'eval(atob(',
    ];

    /**
     * Recurring CVE probe paths, tested against the decoded surface.
     *
     * @var array<int,string>
     */
    private const EXPLOIT_PATHS = [
        '/vendor/phpunit/phpunit/src/util/php/eval-stdin.php',
        '/actuator/gateway/routes', '/actuator/env', '/actuator/heapdump',
        '/_ignition/execute-solution', '/_profiler/phpinfo',
        '/hnap1', '/boaform/admin/formlogin', '/cgi-bin/luci', '/cgi-bin/viewlog.asp',
        '/cgi-bin/mainfunction.cgi', '/cgi-bin/.%2e/', '/cgi-mod/index.cgi',
        '/api/jsonws/invoke', '/console/login/loginform.jsp',
        '/autodiscover/autodiscover.json', '/owa/auth/x.js', '/ecp/y.js',
        '/index.php?s=/index/\\think', '/index.php?s=index/\\think',
        '/solr/admin/info/system', '/druid/indexer/v1/sampler',
        '/nice ports,/trinity.txt.bak', '/telerik.web.ui.webresource.axd',
        '/struts2-showcase/', '/wls-wsat/coordinatortype', '/remote/fgt_lang',
        '/dana-na/auth/url_default/welcome.cgi', '/+cscoe+/logon.html',
        '/geoserver/wms', '/graphql?query={__schema', '/debug/default/view',
        '/?rest_route=/wp/v2/users/', '/wp-json/wp/v2/users/',
        '/.git/objects/', '/laravel/.env', '/ecp/current/exporttool/',
    ];

    /**
     * Well-known administration entry points, tested against the decoded surface.
     *
     * @var array<int,string>
     */
    private const ADMIN_PATHS = [
        '/wp-admin', '/wp-login.php', '/administrator/', '/admin.php', '/admin/login',
        '/phpmyadmin', '/pma/', '/myadmin', '/adminer.php', '/manager/html',
        '/manager/status', '/server-status', '/server-info', '/xmlrpc.php',
        '/solr/#/', '/jenkins/script', '/wp-content/plugins/', '/typo3/index.php',
        '/user/login?destination=', '/rails/info/properties',
    ];

    /**
     * Setup and installation scripts that should not survive deployment.
     *
     * @var array<int,string>
     */
    private const INSTALLER_PATHS = [
        '/install.php', '/setup.php', '/setup-config.php', '/upgrade.php', '/installer/',
        '/install/index.php', '/_install', '/web/install', '/core/install.php',
    ];

    /**
     * The `/.well-known/` suffixes that are ordinary and must not be flagged.
     *
     * @var array<int,string>
     */
    private const WELLKNOWN_OK = [
        'acme-challenge', 'security.txt', 'change-password', 'apple-app-site-association',
        'assetlinks.json', 'openid-configuration', 'oauth-authorization-server',
        'host-meta', 'webfinger', 'nodeinfo', 'traffic-advice', 'dnt-policy.txt',
        'matrix', 'discord', 'gpc.json', 'mta-sts.txt', 'pki-validation', 'ashrae',
        'caldav', 'carddav', 'appspecific',
    ];

    /**
     * Sign-in endpoints, tested as a path suffix or prefix.
     *
     * @var array<int,string>
     */
    private const LOGIN_PATHS = [
        '/login', '/signin', '/sign-in', '/user/login', '/users/sign_in', '/wp-login.php',
        '/admin/login', '/auth/login', '/api/login', '/api/auth', '/oauth/token', '/session',
        '/account/login', '/xmlrpc.php', '/login.php', '/login.aspx', '/dologin',
    ];

    /**
     * Scanner and fuzzer names, tested against the lower-cased User-Agent.
     *
     * @var array<int,string>
     */
    private const SCANNER_UA = [
        'sqlmap', 'nikto', 'nmap scripting engine', 'masscan', 'zgrab', 'nuclei',
        'wpscan', 'acunetix', 'netsparker', 'dirbuster', 'gobuster', 'feroxbuster',
        'ffuf', 'wfuzz', 'arachni', 'openvas', 'qualys', 'zaproxy', 'owasp zap',
        'commix', 'whatweb', 'joomscan', 'droopescan', 'metasploit', 'hydra',
        'havij', 'xray', 'dirsearch', 'nessus', 'w3af', 'skipfish', 'brutus',
    ];

    /**
     * Methods an ordinary website never needs.
     *
     * @var array<int,string>
     */
    private const ODD_METHODS = [
        'TRACE', 'TRACK', 'DEBUG', 'CONNECT',
        'PROPFIND', 'PROPPATCH', 'MKCOL', 'MOVE', 'COPY', 'LOCK', 'UNLOCK', 'SEARCH',
    ];

    /**
     * The codes that are enough, ON THEIR OWN, to say a person was not driving.
     *
     * READ BY Score\Rules::ruleHostileProbe(), AND THAT IS WHY IT LIVES HERE. The detection
     * plane and the scoring plane were disconnected: this file named an exploit probe on the
     * hit, Sessionizer folded the codes up into the session, and the ruleset never looked at
     * them — so a client that requested nothing but `/xmlrpc.php`, `/main/xmlrpc.php` and
     * `/new/xmlrpc.php` tripped no rule at all, scored 15, and was published as a HUMAN
     * session. A tool whose headline claim is "we can tell a person from a scraper" cannot put
     * a WordPress exploit sweep in the human population.
     *
     * IT IS NOT THE SAME SET AS `severity: high`, and the difference is the whole care in this
     * list. Severity answers "how bad is this if it worked"; this answers "could a browser with
     * a person behind it have produced it by accident". Each row's own `over` paragraph decides
     * membership, and every high-severity code NOT here was excluded for the reason that
     * paragraph states:
     *
     *   atk_traversal            a JavaScript bundler emits `../` inside a source-map URL, and
     *                            devtools fetches it from a real browser.
     *   atk_sql_injection        documentation sites, developer forums and any query box.
     *   atk_template_injection   an un-rendered `{{name}}` in a share link, which is a broken
     *                            front end rather than an attacker.
     *   atk_backup_file (med)    a downloads directory serving `release-1.2.tar.gz`.
     *   atk_xss (med)            a bug-bounty programme, or a search box with HTML pasted in.
     *   atk_admin_probe (low)    your own editors reaching `/wp-login.php`. The table calls this
     *                            "the loudest and least alarming row" and means it.
     *   atk_installer_probe      a site that is genuinely being upgraded right now.
     *   atk_login_probe (info)   one of these is a person signing in.
     *   atk_method_abuse         a real WebDAV, CalDAV or SVN endpoint.
     *   atk_proxy_probe          a machine that IS a forward proxy.
     *   atk_wellknown_abuse      a private convention under that prefix.
     *
     * What is left is seven patterns no browser emits by accident: a JNDI lookup, a request for
     * `/etc/passwd` or `.git/config`, a published CVE probe path, shell metacharacters with a
     * shell verb, an address only a server would fetch, a User-Agent that names a fuzzer, and a
     * crawler claim answered from a rented cloud machine.
     *
     * A code that over-reports is still worth SEEING — the Attacks view lists every one of them
     * — it is simply not worth a verdict on its own. The weaker codes reach the scorer through
     * Score\Rules::ruleProbeSweep() instead, which asks what the server ANSWERED before it says
     * anything.
     *
     * @var array<int,string>
     */
    public const DECISIVE = [
        'atk_sensitive_file',
        'atk_command_injection',
        'atk_log4shell',
        'atk_ssrf',
        'atk_known_exploit',
        'atk_scanner_ua',
        'atk_crawler_impersonation',
    ];

    /**
     * Is this code one a verdict may rest on with no corroboration?
     *
     * An unknown code answers false. A document written by a newer detector can carry a code
     * this build has never heard of, and inferring "decisive" from a name would be exactly the
     * guess the whole file refuses to make.
     */
    public static function isDecisive(string $code): bool
    {
        return in_array($code, self::DECISIVE, true);
    }

    /**
     * The catalogue entry for one code, with a safe fallback for an unknown one.
     *
     * An older `hit_rules_i` can have written a code this build no longer defines. The panel
     * must still be able to render it rather than hiding a finding it cannot name — the same
     * contract Score\Rules::describe() keeps for scoring reasons.
     *
     * @return array{label:string,family:string,severity:string,what:string,misses:string,over:string}
     */
    public static function describe(string $code): array
    {
        return self::RULES[$code] ?? [
            'label'    => $code,
            'family'   => 'other',
            'severity' => 'med',
            'what'     => 'This panel version has no description for that rule code. It was written by a '
                . 'different version of the detector.',
            'misses'   => 'Unknown.',
            'over'     => 'Unknown.',
        ];
    }

    /** Every code this build can write, for the filters and the facet scoping. */
    public static function codes(): array
    {
        return array_keys(self::RULES);
    }

    /**
     * The codes belonging to one family.
     *
     * @return array<int,string>
     */
    public static function family(string $family): array
    {
        $out = [];
        foreach (self::RULES as $code => $rule) {
            if ($rule['family'] === $family) {
                $out[] = $code;
            }
        }
        return $out;
    }

    /**
     * The families, in the order the view bands them.
     *
     * @return array<string,string> family key => label
     */
    public static function families(): array
    {
        return [
            'disclosure'    => 'File disclosure',
            'injection'     => 'Injection',
            'exploit'       => 'Known exploits',
            'credential'    => 'Credential attacks',
            'recon'         => 'Reconnaissance',
            'impersonation' => 'Impersonation',
        ];
    }

    /**
     * Judge one hit document and return the codes that fired, in table order.
     *
     * Reads only fields Parser::normalize() has already produced, so it can run inside the
     * same pass with nothing fetched and nothing enriched. The return is deliberately a LIST
     * and not a verdict: a hit is not "an attack", it is a request that matched one or more
     * named patterns, and what the server answered decides what that is worth.
     *
     * The order of the tests is cost-ascending. The surface is decoded once and shared; the
     * cheap `str_contains` sweeps run before anything else; the impersonation test, which
     * needs enrichment that may not be there, runs last and stays silent when it is absent.
     *
     * @param array<string,mixed> $hit A document as Parser::normalize() built it.
     * @return array<int,string>
     */
    public static function of(array $hit): array
    {
        $path   = (string) ($hit['path_s'] ?? '');
        $query  = (string) ($hit['query_s'] ?? '');
        $method = strtoupper((string) ($hit['method_s'] ?? ''));

        $surface = self::surface($path, $query);
        $found = [];

        if (self::any($surface, self::TRAVERSAL)) {
            $found['atk_traversal'] = true;
        }
        if (self::any($surface, self::SENSITIVE)) {
            $found['atk_sensitive_file'] = true;
        }
        if (self::any($surface, self::BACKUP)) {
            $found['atk_backup_file'] = true;
        }
        if (self::any($surface, self::SQLI)) {
            $found['atk_sql_injection'] = true;
        }
        if (self::any($surface, self::CMDI) || self::backtickPair($surface)) {
            $found['atk_command_injection'] = true;
        }
        if (self::any($surface, self::TEMPLATE) || self::dollarBrace($surface)) {
            $found['atk_template_injection'] = true;
        }
        if (self::any($surface, self::JNDI)) {
            $found['atk_log4shell'] = true;
            unset($found['atk_template_injection']);
        }
        if (self::any($surface, self::SSRF)) {
            $found['atk_ssrf'] = true;
        }
        if (self::any($surface, self::XSS)) {
            $found['atk_xss'] = true;
        }
        if (self::any($surface, self::EXPLOIT_PATHS)) {
            $found['atk_known_exploit'] = true;
        }
        if (self::any($surface, self::ADMIN_PATHS)) {
            $found['atk_admin_probe'] = true;
        }
        if (self::any($surface, self::INSTALLER_PATHS)) {
            $found['atk_installer_probe'] = true;
        }
        if (self::wellKnownAbuse($surface)) {
            $found['atk_wellknown_abuse'] = true;
        }
        if (($method === 'POST' || $method === 'PUT') && self::any($surface, self::LOGIN_PATHS)) {
            $found['atk_login_probe'] = true;
        }
        if ($method !== '' && in_array($method, self::ODD_METHODS, true)) {
            $found['atk_method_abuse'] = true;
        }
        if (self::proxyProbe($hit)) {
            $found['atk_proxy_probe'] = true;
        }
        if (self::any(strtolower((string) ($hit['ua_s'] ?? '')), self::SCANNER_UA)) {
            $found['atk_scanner_ua'] = true;
        }
        if (self::impersonation($hit)) {
            $found['atk_crawler_impersonation'] = true;
        }

        $out = [];
        foreach (array_keys(self::RULES) as $code) {
            if (isset($found[$code])) {
                $out[] = $code;
            }
        }
        return $out;
    }

    /**
     * Judge a hit and write the result onto it — THE ONE CALL SITE EVERY INGEST PATH USES.
     *
     * Returned rather than mutated in place so a caller cannot half-apply it, and stamped with
     * `hit_rules_i` UNCONDITIONALLY, which is the whole three-state contract: a document that
     * has been looked at says so even when nothing matched, and a document that says nothing
     * was never looked at. Writing the version only when a flag fired would have made "clean"
     * and "not evaluated" the same absence, and the view would report a deployment gap as a
     * quiet week.
     *
     * `hit_flags_ss` is written only when something fired. A multi-valued field with no values
     * is not a document that matched nothing, it is a document with a field nobody set, and
     * SPEC §4.1 is explicit that absent must stay absent.
     *
     * @param array<string,mixed> $hit
     * @return array<string,mixed>
     */
    public static function apply(array $hit): array
    {
        $flags = self::of($hit);

        $hit['hit_rules_i'] = self::RULE_VERSION;
        if ($flags !== []) {
            $hit['hit_flags_ss'] = $flags;
        }

        return $hit;
    }

    /**
     * The single lower-cased string every substring rule is tested against.
     *
     * Path and query joined, backslashes folded to forward slashes, overlong UTF-8 dots
     * rewritten, then percent-decoded twice — `%252e%252e%252f` is `../` and a detector that
     * decodes once does not see it. Bounded at MAX_SURFACE before any decoding, so a crafted
     * query string cannot make the decode itself expensive.
     */
    private static function surface(string $path, string $query): string
    {
        $raw = $query === '' ? $path : $path . '?' . $query;
        if (strlen($raw) > self::MAX_SURFACE) {
            $raw = substr($raw, 0, self::MAX_SURFACE);
        }

        $s = strtolower($raw);
        $s = str_replace(['%c0%ae', '%e0%40%ae', '%c0%2e', '%uff0e'], '.', $s);
        $s = str_replace(['%c0%af', '%c1%9c', '%u2215'], '/', $s);

        for ($i = 0; $i < self::DECODE_ROUNDS; $i++) {
            $decoded = rawurldecode($s);
            if ($decoded === $s) {
                break;
            }
            $s = strtolower($decoded);
        }

        return str_replace('\\', '/', $s);
    }

    /**
     * Does the subject contain any of the needles?
     *
     * @param array<int,string> $needles
     */
    private static function any(string $subject, array $needles): bool
    {
        if ($subject === '') {
            return false;
        }
        foreach ($needles as $needle) {
            if (str_contains($subject, $needle)) {
                return true;
            }
        }
        return false;
    }

    /**
     * A `${…}` construct that is not one of the JNDI forms.
     *
     * Tested separately from the TEMPLATE list because the bare `${` is far too common on its
     * own — it appears in un-rendered JavaScript template literals that leak into URLs — so it
     * only counts when it CLOSES, which an accidental one usually does not.
     */
    private static function dollarBrace(string $surface): bool
    {
        $open = strpos($surface, '${');
        return $open !== false && strpos($surface, '}', $open) !== false;
    }

    /**
     * A matched pair of backticks, which is command substitution and not punctuation.
     *
     * A single backtick appears in ordinary text often enough to be worthless; a pair with
     * something between them does not.
     */
    private static function backtickPair(string $surface): bool
    {
        $first = strpos($surface, '`');
        return $first !== false && strpos($surface, '`', $first + 1) !== false;
    }

    /**
     * A `/.well-known/` request for a suffix nobody registered.
     *
     * The directory ACME forces to be writable is the favourite place to leave a shell, so
     * anything under it that is not on the ordinary list is worth naming. The allowlist is
     * checked against the first segment after the prefix, so `/.well-known/acme-challenge/xyz`
     * is ordinary and `/.well-known/pki.php` is not.
     */
    private static function wellKnownAbuse(string $surface): bool
    {
        $at = strpos($surface, '/.well-known/');
        if ($at === false) {
            return false;
        }

        $rest = substr($surface, $at + 13);
        $cut = strcspn($rest, '/?');
        $segment = substr($rest, 0, $cut);
        if ($segment === '') {
            return false;
        }

        return !in_array($segment, self::WELLKNOWN_OK, true);
    }

    /**
     * An absolute-URI request target naming a host this server does not answer for.
     *
     * Parser::extractRequest() sets `_abs_host` when the request line carried a scheme and an
     * authority instead of an origin-form path. Compared against `host_s`, which is the vhost
     * the webserver decided it was: equal means an ordinary absolute-form request (some
     * clients and some proxies in front of us send them), different means the client asked
     * this machine to go and fetch somebody else's site.
     *
     * AN UNKNOWN VHOST IS NOT A MISMATCH. This used to answer TRUE when `host_s` was absent —
     * `return $own === '' || $abs !== $own` — which is a finding manufactured out of a missing
     * measurement, the one thing this project refuses to publish. A log format with no `%v` and
     * no configured source host produces no `host_s` at all, so on those installations EVERY
     * absolute-form request was reported as an open-proxy probe, and absolute form is sent by
     * more ordinary clients than it should be. There is nothing to compare the claimed authority
     * against, so there is nothing to say.
     *
     * @param array<string,mixed> $hit
     */
    private static function proxyProbe(array $hit): bool
    {
        $abs = strtolower(trim((string) ($hit['_abs_host'] ?? '')));
        if ($abs === '') {
            return false;
        }
        $own = strtolower(trim((string) ($hit['host_s'] ?? '')));
        if ($own === '') {
            return false;
        }

        return $abs !== $own;
    }

    /**
     * A declared major crawler answering from a rented cloud machine.
     *
     * Three conditions, all required, and the third is what keeps it honest: the UA must name
     * a crawler, that crawler must be in a category whose operators run their own
     * infrastructure, and the reverse DNS must be PRESENT and be a general-purpose tenant
     * name. Absent reverse DNS yields false rather than true — an enrichment that did not run
     * is not evidence, which is the rule the whole scorer is built on.
     *
     * @param array<string,mixed> $hit
     */
    private static function impersonation(array $hit): bool
    {
        if (($hit['ua_bot_b'] ?? null) !== true) {
            return false;
        }
        $category = (string) ($hit['ua_bot_cat_s'] ?? '');
        if (!in_array($category, self::IMPERSONABLE_CATEGORIES, true)) {
            return false;
        }

        $rdns = strtolower(trim((string) ($hit['rdns_s'] ?? '')));
        if ($rdns === '') {
            return false;
        }
        $rdns = rtrim($rdns, '.');

        foreach (self::TENANT_RDNS as $suffix) {
            if (str_ends_with($rdns, $suffix)) {
                return true;
            }
        }

        return false;
    }
}
