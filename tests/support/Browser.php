<?php
/**
 * Loghound — a real browser, for the assertions no amount of source reading can make.
 *
 * ## Why this file exists
 *
 * The rest of this suite tests the panel's front end by READING ITS SOURCE: a test opens
 * `responsive.js`, finds a function, and asserts that a particular call appears inside it.
 * That is cheap, it needs no toolchain, and it catches a great deal. It also has one blind
 * spot, and the blind spot is expensive.
 *
 * A source-reading test can only ever confirm that the code says what the author meant. It
 * cannot confirm that the BROWSER AGREES. The import map is the case that proved it: the map
 * was generated, the map was emitted, a test parsed the generated JSON and agreed with itself
 * that every module was listed and every URL was stamped — and Chrome discarded all
 * thirty-two entries as bare specifiers and loaded the whole graph unversioned. Every
 * assertion passed. The feature did nothing. The operator kept hard-reloading after releases.
 *
 * The only witness that can settle a question like that is a browser, so this is one:
 * headless Chrome, driven over the DevTools protocol, from PHP, with no Node, no npm and no
 * build step — the three things this product does not have and is not going to grow.
 *
 * ## What it is for, and what it is NOT for
 *
 * FOR: things only a rendering engine knows. Did the browser accept the import map. Did it
 * fetch the versioned URL or the bare one. Does this element's computed left edge line up
 * with its sibling's. Did anything at all reach the console. Does the Close button in a
 * dialog opened from inside another dialog actually close it.
 *
 * NOT FOR: anything a PHP test can already answer. A browser test is two orders of magnitude
 * slower than a string comparison and has a process tree to clean up. Every check that can be
 * made without one still is.
 *
 * ## Skipping is deliberate, and it is not a way out
 *
 * This repository is public and is expected to clone-and-test on a bare box. If no Chrome is
 * found the browser tests SKIP, loudly, by name — they never pass vacuously. The static
 * assertions beside them run everywhere and always, so a machine with no browser still fails
 * on a bare specifier; the browser is what additionally proves the map is APPLIED.
 *
 * Point it at a specific binary with `LOGHOUND_CHROME=/path/to/chrome`.
 *
 * ## The panel it drives
 *
 * A COPY of the installation, in a temporary directory, with a throwaway configuration and a
 * throwaway Basic password generated per run. Never the operator's own `config/loghound.php`
 * — that file holds the Opensolr API key and the beacon secret, and a test that wrote to it
 * would be a genuinely bad afternoon for somebody. Demo mode is on, so no Solr is needed and
 * the world is the fixed-seed fixture every other test already uses.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

/**
 * Every Chrome or Chromium on this machine that might be drivable, best first.
 *
 * ORDER, AND WHY. `LOGHOUND_CHROME` wins outright, so an operator or a CI image can name one
 * exactly. Then the conventional install locations, because a browser the machine's owner
 * installed on purpose is the one most likely to work. Playwright's caches come last and
 * NEWEST FIRST: this product does not depend on Playwright and will not, but there is no
 * reason to make a developer install a second Chrome when one is already on disk — and an old
 * cache left behind by an upgrade is exactly the one that takes a minute to start or never
 * publishes a port at all, which is why the list is a list rather than a single answer.
 *
 * @return array<int,string>
 */
function lh_browser_candidates(): array
{
    $env = (string) getenv('LOGHOUND_CHROME');
    $out = [];
    if ($env !== '') {
        $out[] = $env;
    }

    foreach ([
        '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
        '/Applications/Chromium.app/Contents/MacOS/Chromium',
        '/usr/bin/google-chrome',
        '/usr/bin/google-chrome-stable',
        '/usr/bin/chromium',
        '/usr/bin/chromium-browser',
        '/snap/bin/chromium',
    ] as $c) {
        $out[] = $c;
    }

    $cached = [];
    foreach ([
        (string) getenv('HOME') . '/Library/Caches/ms-playwright/*/chrome-*/chrome-headless-shell',
        (string) getenv('HOME') . '/.cache/ms-playwright/*/chrome-*/chrome-headless-shell',
    ] as $pattern) {
        foreach (glob($pattern) ?: [] as $c) {
            $cached[] = $c;
        }
    }
    rsort($cached);
    foreach ($cached as $c) {
        $out[] = $c;
    }

    return array_values(array_filter($out, static fn (string $c): bool => is_file($c) && is_executable($c)));
}

/**
 * Whether this machine has anything at all that could run the browser checks.
 */
function lh_browser_binary(): ?string
{
    $all = lh_browser_candidates();

    return $all === [] ? null : $all[0];
}

/**
 * The throwaway Basic password for this run. Random, in memory, never written to the repo.
 */
function lh_browser_password(): string
{
    static $pw = null;
    if ($pw === null) {
        $pw = bin2hex(random_bytes(9));
    }
    return $pw;
}

/**
 * A complete, self-contained installation in a temporary directory, built once per run.
 *
 * `src/` and `public/` are COPIED rather than symlinked, because `__DIR__` resolves symlinks:
 * a symlinked `public/` would make `public/index.php` read the REAL `config/loghound.php`,
 * which is the operator's, which is the one file this must never touch. A copy of about five
 * megabytes takes well under a second and buys complete isolation.
 *
 * `Assets::root()` is `dirname(__DIR__)` from the copied `src/Assets.php`, so the import map
 * this tree serves is built from the copied `public/assets` — the same files, at the same
 * modification times, which `cp -p` preserves so the version stamps are the real ones.
 *
 * @return string The tree's root, holding `src/`, `public/`, `config/` and `var/`.
 */
function lh_browser_tree(): string
{
    static $root = null;
    if ($root !== null) {
        return $root;
    }

    $repo = dirname(__DIR__, 2);
    $root = lh_tmpdir('lh_browser');

    foreach (['src', 'public'] as $dir) {
        $ok = 0;
        $out = [];
        exec('cp -Rp ' . escapeshellarg($repo . '/' . $dir) . ' ' . escapeshellarg($root . '/' . $dir) . ' 2>&1', $out, $ok);
        if ($ok !== 0) {
            lh_skip('could not copy ' . $dir . '/ into a temporary tree: ' . implode(' ', $out));
        }
    }
    @mkdir($root . '/config', 0750, true);
    @mkdir($root . '/var', 0750, true);

    $config = [
        'site_name' => 'Loghound (browser test)',
        'base_url'  => '',
        'auth' => [
            'mode'          => 'basic',
            'user'          => 'loghound',
            'password_hash' => password_hash(lh_browser_password(), PASSWORD_DEFAULT),
        ],
        'beacon' => ['enabled' => false, 'secret' => ''],
        'solr'   => [
            'mode'           => 'opensolr',
            'base_url'       => 'http://127.0.0.1:9/solr',
            'hits_core'      => 'lh_browser_hits',
            'sessions_core'  => 'lh_browser_sessions',
        ],
        'ui' => ['demo' => true, 'timezone' => 'UTC'],
    ];

    file_put_contents(
        $root . '/config/loghound.php',
        "<?php\n\nreturn " . var_export($config, true) . ";\n"
    );

    register_shutdown_function(static function () use ($root): void {
        lh_rmtree($root);
    });

    return $root;
}

/**
 * The router `php -S` runs in front of the copied panel.
 *
 * TWO JOBS, and only these two. It serves a static file straight off disk when one exists,
 * which is what returning false from a router does. And it turns the `Authorization` header
 * into `PHP_AUTH_USER` / `PHP_AUTH_PW`, because the built-in server does not, and HTTP Basic
 * is the mode this tree is configured for — the panel's own authentication is untouched and
 * is still what decides whether the request is served. There is no bypass here: a wrong
 * password gets the same 401 it would get anywhere else.
 */
function lh_browser_router(string $root): string
{
    $path = $root . '/router.php';
    $code = <<<'PHP'
<?php

declare(strict_types=1);

$file = __DIR__ . '/public' . parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if (is_file($file) && !str_ends_with($file, '.php')) {
    return false;
}

$auth = $_SERVER['HTTP_AUTHORIZATION'] ?? ($_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '');
if (is_string($auth) && stripos($auth, 'basic ') === 0) {
    $pair = (string) base64_decode(substr($auth, 6), true);
    if (str_contains($pair, ':')) {
        [$u, $p] = explode(':', $pair, 2);
        $_SERVER['PHP_AUTH_USER'] = $u;
        $_SERVER['PHP_AUTH_PW'] = $p;
    }
}

require __DIR__ . '/public/index.php';
PHP;
    file_put_contents($path, $code);

    return $path;
}

/**
 * Start the copied panel on a loopback port and return its base URL.
 *
 * The port is claimed by binding it first and closing it, then handing the number to
 * `php -S`. A plain "pick a number and hope" races with every other test process on the
 * machine; this narrows the window to the microseconds between the close and the bind.
 *
 * @return array{base:string,pid:int,root:string}
 */
function lh_browser_serve(): array
{
    static $server = null;
    if ($server !== null) {
        return $server;
    }

    $root = lh_browser_tree();
    $router = lh_browser_router($root);

    $probe = @stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
    if ($probe === false) {
        lh_skip('could not claim a loopback port: ' . $errstr);
    }
    $name = (string) stream_socket_get_name($probe, false);
    $port = (int) substr($name, (int) strrpos($name, ':') + 1);
    fclose($probe);

    /* THE BUILT-IN SERVER IS SINGLE-THREADED, and every card in this panel paints from its own
       fetch. With one worker the browser's requests queue behind each other and a page that
       renders instantly in production takes seconds here, which turns a settle budget into a
       flake. Workers are the supported way to fix that and cost nothing else. */
    $cmd = 'LOGHOUND_TEST=1 PHP_CLI_SERVER_WORKERS=8 ' . escapeshellarg(PHP_BINARY)
        . ' -d display_errors=0 -S 127.0.0.1:' . $port
        . ' -t ' . escapeshellarg($root . '/public')
        . ' ' . escapeshellarg($router)
        . ' > ' . escapeshellarg($root . '/server.out') . ' 2>&1 & echo $!';
    $pid = (int) shell_exec($cmd);
    if ($pid <= 0) {
        lh_skip('could not start the built-in server for the browser checks');
    }

    register_shutdown_function(static function () use ($pid): void {
        @exec('kill -9 ' . $pid . ' 2>/dev/null');
    });

    $base = 'http://127.0.0.1:' . $port;
    for ($i = 0; $i < 120; $i++) {
        $sock = @stream_socket_client('tcp://127.0.0.1:' . $port, $en, $es, 0.2);
        if ($sock !== false) {
            fclose($sock);
            return $server = ['base' => $base, 'pid' => $pid, 'root' => $root];
        }
        usleep(50000);
    }

    lh_skip('the built-in server never came up on ' . $base);
}

/**
 * A headless Chrome, driven over the DevTools protocol.
 *
 * ## Why a hand-written WebSocket client
 *
 * CDP's only transport is a WebSocket, and this repository has no dependencies and is not
 * getting any. The framing this needs is the narrow subset a client actually sends and
 * receives against a loopback DevTools endpoint: a single text opcode, client-masked on the
 * way out, unmasked and unfragmented on the way in. That is about eighty lines, all of it in
 * the three methods at the bottom, and it is far less machinery than a package manager.
 *
 * ## What it collects, and why "any message at all" is the bar
 *
 * Everything the console would show a developer with the panel open: `Log.entryAdded` for the
 * browser's own complaints (a rejected import map, a blocked request, a CSP violation),
 * `Runtime.consoleAPICalled` for anything the page said itself, and `Runtime.exceptionThrown`
 * for what it threw. A test asserts there were NONE of them, which is a deliberately absolute
 * bar: the import-map defect announced itself perfectly clearly in the console and nothing was
 * listening. A page that has something to say has something wrong with it.
 */
final class LhBrowser
{
    /** @var resource */
    private $sock;

    /** The Chrome process, killed on close and again at shutdown. */
    private int $pid = 0;

    /** Unread bytes from the socket, held between frame reads. */
    private string $buf = '';

    /** The CDP message id counter; every command gets its own. */
    private int $seq = 0;

    /** @var array<int,array<string,mixed>> Events collected since the last clear(). */
    private array $events = [];

    /** The throwaway profile directory, removed on close. */
    private string $profile = '';

    /**
     * Launch the browser and attach to its first page target.
     *
     * `--remote-debugging-port=0` makes Chrome choose a free port and write it into
     * `DevToolsActivePort` in the profile, which is the only race-free way to learn it.
     */
    public static function open(): self
    {
        $tried = [];
        foreach (lh_browser_candidates() as $bin) {
            $self = new self();
            $ws = $self->launch($bin);
            if ($ws !== null) {
                $self->connect($ws);
                $self->send('Runtime.enable');
                $self->send('Log.enable');
                $self->send('Page.enable');
                $self->send('Network.enable');

                return $self;
            }
            $self->close();
            $tried[] = $bin;
        }

        lh_skip(
            $tried === []
                ? 'no Chrome or Chromium found; set LOGHOUND_CHROME=/path/to/chrome to run the browser checks'
                : 'no usable browser: none of these published a DevTools port — ' . implode(', ', $tried)
        );
    }

    /**
     * Start one candidate and return its page target's WebSocket URL, or null if it will not.
     *
     * A browser that has not published `DevToolsActivePort` within the budget is not coming;
     * a stale Playwright cache left behind by an upgrade takes a full minute and then fails,
     * and waiting the minute out on every run is not a cost worth paying for a browser the
     * caller has three alternatives to.
     */
    private function launch(string $bin, float $budget = 8.0): ?string
    {
        $this->profile = lh_tmpdir('lh_chrome');
        $cmd = escapeshellarg($bin)
            . ' --headless --disable-gpu --no-sandbox --no-first-run --no-default-browser-check'
            . ' --disable-extensions --disable-background-networking --disable-sync'
            . ' --hide-scrollbars --force-device-scale-factor=1'
            . ' --remote-debugging-port=0'
            . ' --user-data-dir=' . escapeshellarg($this->profile)
            . ' about:blank > /dev/null 2>&1 & echo $!';
        $this->pid = (int) shell_exec($cmd);
        if ($this->pid <= 0) {
            return null;
        }

        $pid = $this->pid;
        register_shutdown_function(static function () use ($pid): void {
            @exec('kill -9 ' . $pid . ' 2>/dev/null');
        });

        $port = 0;
        $portFile = $this->profile . '/DevToolsActivePort';
        $deadline = microtime(true) + $budget;
        while (microtime(true) < $deadline) {
            if (is_file($portFile)) {
                $lines = file($portFile, FILE_IGNORE_NEW_LINES) ?: [];
                if (isset($lines[0]) && (int) $lines[0] > 0) {
                    $port = (int) $lines[0];
                    break;
                }
            }
            usleep(50000);
        }
        if ($port <= 0) {
            return null;
        }

        /* `Connection: close` IS NOT COSMETIC. Chrome's DevTools HTTP endpoint answers with
           keep-alive and no Content-Length, so PHP's http wrapper reads until the socket
           closes — which is `default_socket_timeout`, sixty seconds, on every single call.
           That turned an eight-second budget into a minute per candidate and made the whole
           harness look broken when it was merely waiting. */
        $ctx = stream_context_create(['http' => [
            'timeout' => 2.0,
            'header' => "Connection: close\r\n",
            'ignore_errors' => true,
        ]]);

        $deadline = microtime(true) + $budget;
        while (microtime(true) < $deadline) {
            $list = json_decode((string) @file_get_contents('http://127.0.0.1:' . $port . '/json/list', false, $ctx), true);
            foreach (is_array($list) ? $list : [] as $target) {
                if (($target['type'] ?? '') === 'page' && isset($target['webSocketDebuggerUrl'])) {
                    return (string) $target['webSocketDebuggerUrl'];
                }
            }
            usleep(100000);
        }

        return null;
    }

    /**
     * Send credentials on every request, for the whole session.
     *
     * @param array<string,string> $headers
     */
    public function headers(array $headers): void
    {
        $this->call('Network.setExtraHTTPHeaders', ['headers' => (object) $headers]);
    }

    /**
     * Set the viewport, so a width-dependent layout can be asserted at a named width.
     */
    public function viewport(int $width, int $height): void
    {
        $this->call('Emulation.setDeviceMetricsOverride', [
            'width' => $width,
            'height' => $height,
            'deviceScaleFactor' => 1,
            'mobile' => false,
        ]);
    }

    /**
     * Navigate, wait for load, then wait for the page to go quiet.
     *
     * THE SETTLE IS NOT OPTIONAL. Every card in this panel paints from a `fetch` issued after
     * load, so a check that ran at `load` would be looking at skeletons. Quiet is measured as
     * "no new event for 400ms", capped, which is the cheapest signal that does not require the
     * harness to know how many requests a given view makes.
     */
    public function visit(string $url, float $settle = 0.4, float $budget = 15.0): void
    {
        $this->events = [];
        $this->call('Page.navigate', ['url' => $url], $budget);

        $deadline = microtime(true) + $budget;
        $quiet = microtime(true) + $budget;
        $loaded = false;
        while (microtime(true) < $deadline && microtime(true) < $quiet) {
            $got = $this->pump(0.15);
            if ($got > 0) {
                $quiet = microtime(true) + ($loaded ? $settle : $budget);
            }
            foreach ($this->events as $e) {
                if (($e['method'] ?? '') === 'Page.loadEventFired' && !$loaded) {
                    $loaded = true;
                    $quiet = microtime(true) + $settle;
                }
            }
        }
    }

    /**
     * Let the page run for a while, collecting whatever it says.
     *
     * Used after a synthetic click, where there is nothing to wait FOR by name and the only
     * honest answer is "give it a moment and then look".
     */
    public function settle(float $seconds = 0.6): void
    {
        $end = microtime(true) + $seconds;
        while (microtime(true) < $end) {
            $this->pump(0.1);
        }
    }

    /**
     * Run an expression in the page and return its value.
     *
     * Awaits a promise, so a caller can evaluate something asynchronous and get the result
     * rather than a Promise object. A thrown expression returns null and leaves the throw in
     * the collected messages, where a test that cares will see it.
     *
     * @return mixed
     */
    public function evaluate(string $expression, float $budget = 10.0)
    {
        $reply = $this->call('Runtime.evaluate', [
            'expression' => $expression,
            'returnByValue' => true,
            'awaitPromise' => true,
        ], $budget);

        return $reply['result']['result']['value'] ?? null;
    }

    /**
     * Press something, the way a person would, and wait for whatever it sets off.
     *
     * `click()` rather than a synthesised event: it is what a real press does, it respects
     * `inert` and `pointer-events` exactly as the browser does, and a control that a CSS rule
     * has made unreachable stays unreachable — which is the whole point when the question
     * under test is "does this button work".
     *
     * @return bool Whether an element matching the selector was there to press.
     */
    public function click(string $selector, float $settle = 0.6): bool
    {
        $hit = $this->evaluate(
            '(function () { var n = document.querySelector(' . json_encode($selector) . ');'
            . ' if (!n) { return false; } n.click(); return true; })()'
        );
        $this->settle($settle);

        return $hit === true;
    }

    /**
     * Send a key to the page, through the browser's own input pipeline.
     *
     * Dispatched as a real key event rather than a constructed one, so a handler bound to the
     * document sees exactly what it would see from a keyboard — including the case where
     * something in between has already stopped it.
     */
    public function key(string $key, float $settle = 0.4): void
    {
        $this->call('Input.dispatchKeyEvent', ['type' => 'rawKeyDown', 'key' => $key, 'code' => $key]);
        $this->call('Input.dispatchKeyEvent', ['type' => 'keyUp', 'key' => $key, 'code' => $key]);
        $this->settle($settle);
    }

    /**
     * Everything the console would have shown, since the last visit().
     *
     * @return array<int,string>
     */
    public function messages(): array
    {
        $out = [];
        foreach ($this->events as $e) {
            $method = (string) ($e['method'] ?? '');
            if ($method === 'Log.entryAdded') {
                $entry = $e['params']['entry'] ?? [];
                $out[] = strtoupper((string) ($entry['level'] ?? '?')) . ' '
                    . (string) ($entry['text'] ?? '')
                    . (isset($entry['url']) ? ' (' . $entry['url'] . ')' : '');
            } elseif ($method === 'Runtime.consoleAPICalled') {
                $parts = [];
                foreach ($e['params']['args'] ?? [] as $arg) {
                    $parts[] = (string) ($arg['value'] ?? ($arg['description'] ?? '[object]'));
                }
                $out[] = strtoupper((string) ($e['params']['type'] ?? 'log')) . ' ' . implode(' ', $parts);
            } elseif ($method === 'Runtime.exceptionThrown') {
                $d = $e['params']['exceptionDetails'] ?? [];
                $out[] = 'EXCEPTION ' . (string) ($d['exception']['description'] ?? ($d['text'] ?? 'threw'));
            }
        }

        return $out;
    }

    /**
     * Every URL the page actually fetched, in order.
     *
     * This is the witness for "the import map was APPLIED rather than merely present": a map
     * the browser honoured shows `core.js?v=…`, and a map it discarded shows `core.js`.
     *
     * @return array<int,string>
     */
    public function requests(): array
    {
        $value = $this->evaluate(
            'performance.getEntriesByType("resource").map(function (e) { return e.name; }).join("\n")'
        );

        return $value === null || $value === '' ? [] : explode("\n", (string) $value);
    }

    /** Stop the browser and remove its profile. */
    public function close(): void
    {
        if (is_resource($this->sock)) {
            @fclose($this->sock);
        }
        if ($this->pid > 0) {
            @exec('kill -9 ' . $this->pid . ' 2>/dev/null');
            $this->pid = 0;
        }
        if ($this->profile !== '') {
            lh_rmtree($this->profile);
            $this->profile = '';
        }
    }

    /**
     * Issue a CDP command and wait for the reply carrying its id.
     *
     * Events that arrive while waiting are kept, not dropped: a command is frequently what
     * causes the interesting console message, and a harness that discarded everything that was
     * not the reply would lose exactly the evidence it exists to gather.
     *
     * @param array<string,mixed> $params
     * @return array<string,mixed>
     */
    private function call(string $method, array $params = [], float $budget = 10.0): array
    {
        $id = $this->send($method, $params);
        $deadline = microtime(true) + $budget;
        while (microtime(true) < $deadline) {
            $this->pump(0.1);
            foreach ($this->events as $i => $e) {
                if (($e['id'] ?? null) === $id) {
                    unset($this->events[$i]);
                    return $e;
                }
            }
        }

        return [];
    }

    /**
     * Write one command frame and return the id it was sent under.
     *
     * @param array<string,mixed> $params
     */
    private function send(string $method, array $params = []): int
    {
        $this->seq++;
        $this->frame((string) json_encode([
            'id' => $this->seq,
            'method' => $method,
            'params' => (object) $params,
        ]));

        return $this->seq;
    }

    /**
     * Read whatever has arrived, decode complete frames, and file them.
     *
     * @return int How many messages were taken this pass.
     */
    private function pump(float $wait): int
    {
        $read = [$this->sock];
        $write = null;
        $except = null;
        @stream_select($read, $write, $except, 0, (int) ($wait * 1000000));

        $chunk = @fread($this->sock, 262144);
        if (is_string($chunk) && $chunk !== '') {
            $this->buf .= $chunk;
        }

        $taken = 0;
        while (($payload = $this->take()) !== null) {
            $decoded = json_decode($payload, true);
            if (is_array($decoded)) {
                $this->events[] = $decoded;
                $taken++;
            }
        }

        return $taken;
    }

    /**
     * Pull one complete text frame out of the buffer, or null while it is still partial.
     *
     * A server frame is never masked, so there is no unmasking step; the three length forms
     * are all that has to be understood.
     */
    private function take(): ?string
    {
        if (strlen($this->buf) < 2) {
            return null;
        }
        $len = ord($this->buf[1]) & 0x7F;
        $off = 2;
        if ($len === 126) {
            if (strlen($this->buf) < 4) {
                return null;
            }
            $len = (int) unpack('n', substr($this->buf, 2, 2))[1];
            $off = 4;
        } elseif ($len === 127) {
            if (strlen($this->buf) < 10) {
                return null;
            }
            $len = (int) unpack('J', substr($this->buf, 2, 8))[1];
            $off = 10;
        }
        if (strlen($this->buf) < $off + $len) {
            return null;
        }
        $payload = substr($this->buf, $off, $len);
        $this->buf = substr($this->buf, $off + $len);

        return $payload;
    }

    /** Write one masked client text frame. */
    private function frame(string $payload): void
    {
        $len = strlen($payload);
        $head = chr(0x81);
        if ($len < 126) {
            $head .= chr(0x80 | $len);
        } elseif ($len < 65536) {
            $head .= chr(0x80 | 126) . pack('n', $len);
        } else {
            $head .= chr(0x80 | 127) . pack('J', $len);
        }
        $mask = random_bytes(4);
        $body = '';
        for ($i = 0; $i < $len; $i++) {
            $body .= chr(ord($payload[$i]) ^ ord($mask[$i % 4]));
        }
        stream_set_blocking($this->sock, true);
        @fwrite($this->sock, $head . $mask . $body);
        stream_set_blocking($this->sock, false);
    }

    /** Perform the HTTP upgrade that turns a loopback socket into a WebSocket. */
    private function connect(string $url): void
    {
        $parts = (array) parse_url($url);
        $host = (string) ($parts['host'] ?? '127.0.0.1');
        $port = (int) ($parts['port'] ?? 80);
        $path = (string) ($parts['path'] ?? '/');

        $sock = @stream_socket_client('tcp://' . $host . ':' . $port, $errno, $errstr, 10);
        if ($sock === false) {
            $this->close();
            lh_skip('could not reach the DevTools endpoint: ' . $errstr);
        }
        $this->sock = $sock;

        @fwrite($sock, 'GET ' . $path . " HTTP/1.1\r\n"
            . 'Host: ' . $host . ':' . $port . "\r\n"
            . "Upgrade: websocket\r\nConnection: Upgrade\r\n"
            . 'Sec-WebSocket-Key: ' . base64_encode(random_bytes(16)) . "\r\n"
            . "Sec-WebSocket-Version: 13\r\n\r\n");

        $head = '';
        $deadline = microtime(true) + 10;
        while (!str_contains($head, "\r\n\r\n") && microtime(true) < $deadline) {
            $line = fgets($sock, 4096);
            if ($line === false) {
                break;
            }
            $head .= $line;
        }
        if (!str_contains($head, ' 101 ')) {
            $this->close();
            lh_skip('the DevTools endpoint refused the WebSocket upgrade');
        }

        stream_set_blocking($sock, false);
    }
}

/**
 * Open the panel at one view, already signed in, and hand back the browser.
 *
 * The one-call front door for a browser test: tree, server, browser, credentials and
 * navigation, with every failure along the way a named skip rather than a red failure on a
 * machine that simply has no Chrome.
 *
 * @param array<string,string> $query Extra query parameters, e.g. `['range' => '24h']`.
 */
function lh_browser_panel(string $view = 'overview', array $query = [], int $width = 1440): LhBrowser
{
    $server = lh_browser_serve();
    $browser = LhBrowser::open();
    $browser->headers([
        'Authorization' => 'Basic ' . base64_encode('loghound:' . lh_browser_password()),
    ]);
    $browser->viewport($width, 900);

    $params = array_merge(['v' => $view], $query);
    $browser->visit($server['base'] . '/?' . http_build_query($params));

    return $browser;
}
