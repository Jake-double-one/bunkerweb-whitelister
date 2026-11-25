# Needs validation (prioritised leads, no severity)

## Image job gives a packages:write token to tag-pinned actions on every event; the main/tag condition guards only the publish steps

Fingerprint `ci.yml:image-job:write-token-shared-with-tag-pinned-actions`

Verified in source: the `image` job requests `packages: write` and `security-events: write` at job level (ci.yml:43-46) for every trigger (push to any branch and v* tags, pull_request, weekly cron). The condition `github.event_name != 'pull_request' && (main || v*)` exists only on the three publish steps (ci.yml:92, 100, 109). Before those steps, six `uses:` lines covering five distinct actions (actions/checkout@v7, docker/setup-buildx-action@v4, docker/build-push-action@v7, aquasecurity/trivy-action@v0.36.0 twice, github/codeql-action/upload-sarif@v4) run in the same job with no ref condition; none of the nine `uses:` lines in the job is a 40-hex commit SHA. An action can read the job token without it being passed explicitly. Consequence if one of those action tags is moved or a malicious release is published upstream: its code runs in a job whose token is requested with package write scope, so the step-level ref condition is not the only route to ghcr.io/<repository>, the namespace that README.md:142 and docker-compose.example.yml:10 tell operators to pull by version tag. Corrections to the original wording: (1) the count is five distinct actions before the gate, not seven; (2) the Dependabot path is only one of several: runs on main, on v* tags and on the weekly cron execute the same tag-pinned actions with the same job-level grant, so the exposure to a moved tag does not depend on how Dependabot runs are treated; Dependabot (dependabot.yml:12-15, daily) adds runs of a newly proposed action version on its branch before review. Controls confirmed in source that narrow the claim: no pull_request_target/workflow_run trigger, top-level `contents: read`, code from the repository itself (tests, Dockerfile) runs in the `test` job or inside docker build/run where the token is not passed, and .dockerignore keeps .git out of the build context. Nothing here was or can be demonstrated locally: it needs a malicious third-party action release, and the effective token scope and registry acceptance are repository-host facts. This is a hardening-grade supply-chain exposure conditional on an upstream compromise, not an observed publication.

**Claimed root cause.** Registry write authority is granted to the whole image job instead of to a separate publish job that runs only for main and v* tags, and the actions sharing that job are referenced by mutable tag rather than commit SHA.

### Source trace
1. `.github/workflows/ci.yml:70` (entrypoint, jobs.image.steps (Scan image (report))): Third-party action code selected by a mutable tag (`aquasecurity/trivy-action@v0.36.0`; likewise lines 48, 49, 51, 79, 88) is fetched and executed on the runner at each run; whoever controls that tag upstream controls the code.
2. `.github/dependabot.yml:12` (propagation, updates[github-actions]): Daily Dependabot pull requests change the `uses:` versions; the proposed version is executed by CI on the Dependabot branch before a maintainer reviews it.
3. `.github/workflows/ci.yml:7` (propagation, on): The workflow starts on pull_request, on push to every branch and v* tags (lines 4-6) and on the weekly cron (line 9), so the image job runs for all of them.
4. `.github/workflows/ci.yml:43` (propagation, jobs.image.permissions): contents:read, packages:write and security-events:write are requested for the job unconditionally; there is no `if:` on the job and no `environment:`.
5. `.github/workflows/ci.yml:103` (sink, jobs.image.steps (Image tags)): The namespace ghcr.io/<repository> that the gated steps publish to is the one the job token is scoped for; the conditions on lines 92/100/109 restrict these steps, not the token held by the earlier action steps.

### Verified evidence
- `.github/workflows/ci.yml:43`: Job-level `permissions:` with `packages: write` (line 45) and `security-events: write` (line 46); single job for build, scan and publish.
- `.github/workflows/ci.yml:92`: The main/v* and not-pull_request condition appears only on the login (92), metadata (100) and push (109) steps.
- `.github/workflows/ci.yml:79`: Actions referenced by tag; a search of the workflow finds zero `uses:` references with a 40-hex commit SHA.
- `.github/workflows/ci.yml:9`: The weekly cron runs on the default branch, so tag-pinned actions are re-resolved and run with the publishing token every week without any repository change.
- `.github/dependabot.yml:12`: `package-ecosystem: github-actions` with `interval: daily`.
- `docker-compose.example.yml:10`: Operators pull `ghcr.io/jake-double-one/bunkerweb-whitelister:0.4.6` by tag, not digest (same in README.md:142), so an overwritten tag would reach deployments.

### Exact blockers
- The scenario requires a malicious or compromised upstream action release or a moved action tag; this cannot and must not be produced locally, and no sandbox execution of workflow code is possible offline.
- Whether the GHCR package accepts pushes from this repository's Actions token and allows existing version tags to be overwritten (package 'Manage Actions access' and tag immutability settings are not in source).
- Whether the repository or organisation enforces an allowed-actions list or mandatory SHA pinning, and which default workflow-token setting applies (Settings > Actions; not in source).
- The effective GITHUB_TOKEN scope on Dependabot-triggered and fork pull_request runs (shown only in the run log). This affects only the pre-review Dependabot path; runs on main, v* tags and the cron request the write scope regardless.

### Bounded local plan
Source reading only: confirm in .github/workflows/ci.yml that `packages: write` is at job level (line 45), that the ref condition is only on lines 92, 100 and 109, and that no `uses:` value ends in a 40-hex commit SHA. Verified this way by v3-1; no target code needs to run.

### Owner-observed deployment plan
Repository owner, read-only: (1) open the latest CI run on main and the latest Dependabot-triggered run, expand `Set up job` of the image job and read the `GITHUB_TOKEN Permissions` block for `Packages: write`; (2) check Settings > Actions > General for allowed actions, the SHA-pinning requirement and default token permissions; (3) open the package settings and read `Manage Actions access` and whether version tags can be overwritten; (4) check tag and branch rulesets. Do not test by pushing an image.

## Example compose leaves a second, untrusted path from BunkerWeb to the whitelister (bw-universe)

Fingerprint `docker-compose.example.yml:whitelister:dual-network:bunkerweb-unpinned-on-bw-universe-outside-TRUSTED_PROXIES`

In docker-compose.example.yml the whitelister and bunkerweb (and bw-scheduler) share two networks, bw-services and bw-universe. Only bunkerweb's bw-services address is fixed (10.20.30.2); .env.example trusts exactly that address (TRUSTED_PROXIES=10.20.30.2/32) and allows list downloads only from 10.20.30.0/24. The reverse-proxy target and the list URL use the name `whitelister`, which has an address on both networks. If BunkerWeb connects over bw-universe, its source address (dynamic, 10.20.40.0/24) is not a trusted proxy: X-Forwarded-For is ignored and every visitor is treated as BunkerWeb itself. Re-run in the sandbox with the example values (in-process, dummy secrets): peer 10.20.40.3 with X-Forwarded-For 203.0.113.50 resolves to 10.20.40.3; an invitation redeemed that way lists 10.20.40.3 instead of the guest's address and spends one of the link's address slots (the guest gets no access); three wrong passwords from three different forwarded addresses lock a fourth visitor with the correct password (429), while over the pinned address each visitor keeps an own counter (four wrong passwords, four times 401) and the correct password logs in (303); /ips.txt with the correct token answers 200 from 10.20.30.9 and 403 from 10.20.40.9, so a scheduler download over bw-universe would be refused. The control fails closed: no peer can choose a client identity. The effect is on availability (login lock for the operator, doubling up to 1 h while failures continue; invitations that do not admit the guest; possibly a stale list) and on audit attribution, not on access to the whitelist. Whether BunkerWeb or the scheduler ever use the bw-universe leg depends on Docker's name resolution for containers sharing two networks and on how BunkerWeb 1.6.17 resolves the upstream name; neither is determined by this repository, and the file itself marks the BunkerWeb services as a sketch.

**Claimed root cause.** The example attaches the whitelister to bw-universe (needed only for outbound calls to bw-api) while bunkerweb and bw-scheduler are also on that network without fixed addresses, and TRUSTED_PROXIES / LIST_ALLOWED_NETWORKS name only the bw-services side. The proxy hop is pinned by address on one of two possible legs but selected by a name that resolves on both.

### Source trace
1. `docker-compose.example.yml:39` (entrypoint, services.whitelister.labels): BunkerWeb is told to proxy visitor requests to http://whitelister:8080, a service name rather than an address on one network.
2. `docker-compose.example.yml:20` (propagation, services.whitelister.networks): The whitelister joins bw-universe in addition to bw-services (line 19), so the name has an address on both networks.
3. `docker-compose.example.yml:51` (propagation, services.bunkerweb.networks): bunkerweb joins bw-universe with no ipv4_address; only its bw-services address is fixed (line 53). bw-scheduler (lines 62-64) shares both networks as well.
4. `.env.example:15` (propagation, TRUSTED_PROXIES): Only 10.20.30.2/32 is trusted; BunkerWeb's bw-universe address is outside it.
5. `whitelister/security.py:256` (propagation, resolve_client_ip): A peer outside TRUSTED_PROXIES is returned as the client and the forwarding header is not read (observed: peer 10.20.40.3 -> (10.20.40.3, False); peer 10.20.30.2 -> (203.0.113.50, True)).
6. `whitelister/app.py:476` (propagation, login): The login throttle key is derived from the resolved address, so all visitors arriving over the untrusted leg share one key; open_invite keys the invitation throttle the same way (line 732).
7. `whitelister/app.py:789` (sink, invite_redeem): store.upsert lists the resolved address (the proxy's own) under the invitation's name; the same address goes to the audit log (line 346).

### Verified evidence
- `docker-compose.example.yml:53`: bunkerweb is pinned to 10.20.30.2 on bw-services only; the comment at lines 48-49 says the pin exists so TRUSTED_PROXIES can name the ingress alone.
- `docker-compose.example.yml:20`: whitelister is a member of bw-universe ('reachable to bw-api'), the second network it shares with bunkerweb and bw-scheduler; no ports are published.
- `docker-compose.example.yml:2`: The BunkerWeb services are declared as only sketched (also line 45), so the operator's real attachment is not fixed by this file.
- `.env.example:15`: TRUSTED_PROXIES=10.20.30.2/32.
- `.env.example:24`: LIST_ALLOWED_NETWORKS=10.20.30.0/24; in the sandbox /ips.txt with the correct token returned 200 for peer 10.20.30.9 and 403 for peer 10.20.40.9.
- `whitelister/security.py:256`: Untrusted peer: the TCP peer is the client and the header is ignored. Sandbox run (check-v3-2-universe-leg.txt, example values, LOGIN_MAX_FAILURES=3): redeeming via peer 10.20.40.3 with XFF 203.0.113.50 stored 10.20.40.3; via peer 10.20.30.2 with XFF 203.0.113.51 stored 203.0.113.51; three wrong passwords from three XFF values via 10.20.40.3 (401 each) were followed by 429 for a fourth XFF with the correct password, while the same login via 10.20.30.2 returned 303.
- `whitelister/app.py:284`: redeemer_network accepts the private proxy address because ALLOW_PRIVATE=yes (.env.example:36), so the wrong address is stored rather than refused.
- `whitelister/security.py:146`: LoginThrottle: after max_failures the key is locked for lock_seconds, doubling per further failure up to MAX_LOCK = 3600 s; with one shared key any visitor's failures extend the operator's lock.

### Exact blockers
- Not source-visible and not observable locally (no Docker in the sandbox): which address or addresses Docker's embedded DNS returns to the bunkerweb and bw-scheduler containers for `whitelister` when they share two networks with it, and whether the order is stable.
- Not source-visible: how BunkerWeb 1.6.17 resolves REVERSE_PROXY_HOST (once at configuration load or per request, first address or rotation over all), and which address the scheduler's whitelist download uses; BunkerWeb's source is not part of this repository.
- Not source-visible: whether the operator's real compose file keeps both containers on both networks as in the example, which the file itself calls a sketch.

### Bounded local plan
The app-side half is settled in-process (harness.py in the verifier scratch, TRUSTED_PROXIES=10.20.30.2/32, LIST_ALLOWED_NETWORKS=10.20.30.0/24, dummy password and list token, no BW_API_URL): requests with ASGI peer 10.20.40.3 are attributed to 10.20.40.3 regardless of X-Forwarded-For. The remaining half needs Docker on an isolated host: bring up the example with dummy secrets and run `getent hosts whitelister` several times inside the bunkerweb and bw-scheduler containers, noting whether a 10.20.40.x address is returned.

### Owner-observed deployment plan
Read-only owner check on the running stack: `docker exec bunkerweb getent hosts whitelister` (same for bw-scheduler); in the whitelister's JSON audit lines on stdout look for client addresses in 10.20.40.0/24; open the login page through BunkerWeb several times and compare the address shown with your real public address; check the scheduler's whitelist download job for 403 answers from /ips.txt. If a bw-universe address appears, either point REVERSE_PROXY_HOST and the list URLs at the whitelister's bw-services address (give it a fixed one), or give bunkerweb a fixed bw-universe address and add it to TRUSTED_PROXIES (and the scheduler's network to LIST_ALLOWED_NETWORKS), or put the bw-api call path on a separate network so the whitelister shares only bw-services with bunkerweb and the scheduler; then adjust docker-compose.example.yml and .env.example the same way.

## Trailing-slash redirect answers with an absolute http:// URL that repeats the invitation token path

Fingerprint `whitelister/app.py:create_app:redirect-slashes-absolute-http-location`

The app keeps Starlette's automatic trailing-slash redirect. A path with a trailing slash whose slash-less form matches a route (/i/<anything>/, /login/, /entries/, /invites/ ...) is answered with 307 and an absolute Location built from the ASGI scheme and the Host header. Uvicorn serves plain HTTP with proxy_headers=False, so behind a TLS-terminating proxy the scheme is always http: https://host/i/<token>/ is answered with Location: http://host/i/<token>. The redirect is produced by the router before any handler runs, so it needs no valid token and no session, and it ignores COOKIE_SECURE, PUBLIC_URL and X-Forwarded-Proto. Reproduced locally in-process: this is the response the app hands to the proxy. Whether a client then really sends the token path in cleartext is not established: it needs (1) a link with a trailing slash, which the app itself never produces, (2) a client without HSTS state for the host, and (3) a proxy that passes the Location header unchanged. On top of that an on-path observer is needed for any harm. With HSTS=yes the app adds the HSTS header to the same 307, which protects browsers that honour it, but the Location stays http://.

**Claimed root cause.** create_app builds FastAPI without redirect_slashes=False, so Starlette's Router answers a non-matching path whose slash variant matches with RedirectResponse(URL(scope=...)), an absolute URL from the scope scheme and the Host header. The scope scheme is http by construction (uvicorn without TLS, proxy_headers=False), and this redirect does not go through public_origin, which forces https when COOKIE_SECURE is on.

### Source trace
1. `whitelister/app.py:754` (entrypoint, create_app.invite_page route registration): GET /i/{token} is registered without a trailing slash; an anonymous request for /i/<token>/ (likewise /login/, /entries/, /invites/) matches no route, while its slash-less form does.
2. `whitelister/__main__.py:29` (propagation, main): uvicorn.run serves plain HTTP with proxy_headers=False and forwarded_allow_ips=[], so the ASGI scope scheme is 'http' for every request, also for one that reached the proxy over https; X-Forwarded-Proto is ignored.
3. `whitelister/app.py:152` (sink, create_app): FastAPI(...) is built with the default redirect_slashes=True: the router returns 307 with Location '<scope scheme>://<Host><path without slash>', an absolute http:// URL that repeats the token path.

### Verified evidence
- `whitelister/app.py:152`: FastAPI is constructed with docs disabled but without redirect_slashes=False. Verifier's own sandboxed in-process check (httpx ASGITransport, scheme http, Host wl.example, default COOKIE_SECURE=yes): GET /i/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB/ gave 307 with Location http://wl.example/i/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB and no Strict-Transport-Security header; POST /login/ and GET /login/ gave 307 to http://wl.example/login; GET /entries/ gave 307 to http://wl.example/entries. The same Location came back with X-Forwarded-Proto: https and with PUBLIC_URL=https://wl.example. With HSTS=yes the 307 carried Strict-Transport-Security, the Location was still http://. The token in the check was a dummy that matches no invitation (the slash-less path answers 404), so the redirect does not depend on a valid token.
- `whitelister/app.py:281`: public_origin uses https whenever COOKIE_SECURE is on (or PUBLIC_URL); this is the scheme the app intends for its own links. The framework redirect does not use it.
- `whitelister/config.py:231`: HSTS defaults to off (also HSTS=no in .env.example), so by default the app's own 307 carries no HSTS header; protection of the follow-up request then depends on what the proxy adds.
- `whitelister/app.py:106`: The security-headers middleware wraps the router, so with HSTS=yes the header is also set on the redirect. It sets no rule for the Location header.

### Exact blockers
- Whether the deployed BunkerWeb adds Strict-Transport-Security to this 307 (or the host is already known as HSTS to the client) is a deployment fact outside this repository; with it, browsers upgrade the redirect and nothing goes out in cleartext.
- Whether BunkerWeb passes the upstream Location header unchanged, and whether it accepts the following cleartext request on port 80 for this host, is a deployment fact; the compose example sets no rule for either.
- Whether a link with a trailing slash ever reaches a guest or the operator is not visible in source: the app never emits one (links come from public_origin plus a slash-less path), so a person, a messenger, a mail client or an attacker who hands over a /login/ link has to add the slash.
- Any harm needs an observer on the network path between the client and the proxy at the moment of the cleartext request; this cannot be observed locally.

### Bounded local plan
In-process with httpx.ASGITransport, base URL scheme http (as uvicorn reports it), default settings and dummy secrets: GET /i/<any 32 characters>/ and POST /login/, do not follow redirects, read status and Location. Current result: 307 with an absolute http:// Location. Regression case after the fix (redirect_slashes=False on the FastAPI constructor): both requests answer 404 and no response of the app carries an absolute http:// Location.

### Owner-observed deployment plan
The owner sends, from their own machine and with a non-browser client that does not follow redirects, GET https://<own host>/i/x/ and GET https://<own host>/login/ through BunkerWeb (x is a dummy, no real invitation token), and records the status, the Location header and whether Strict-Transport-Security is present on that response. Read-only; nothing is changed and no real token is used.

## /ips.txt direct-request gate ignores TRUSTED_PROXIES and the configured CLIENT_IP_HEADER

Fingerprint `whitelister/app.py:ips_txt:direct-gate-ignores-trusted-proxies-and-client-ip-header`

GET /ips.txt serves the active whitelist when the TCP peer is inside LIST_ALLOWED_NETWORKS, the optional LIST_TOKEN matches, and none of five fixed header names (x-forwarded-for, forwarded, x-real-ip, x-forwarded-host, x-forwarded-proto) is present. The gate does not consult settings.trusted_proxies or settings.client_ip_header, although the rest of the app uses exactly those two settings to decide whether a request was relayed. Re-derived at 0e90ff4 and reproduced in the sandbox (in-process ASGI, dummy secrets, empty list, no network) with TRUSTED_PROXIES=10.20.30.2/32, LIST_ALLOWED_NETWORKS=10.20.30.0/24 and LIST_TOKEN unset: a request from peer 10.20.30.2 with no header, or with only CF-Connecting-IP: 198.51.100.9, returns 200 and the list header line, both with the default CLIENT_IP_HEADER and with CLIENT_IP_HEADER=CF-Connecting-IP; in the latter case /login renders 198.51.100.9 as the client for the same request shape. Any of the five listed names gives 403, a public peer gives 403, and with LIST_TOKEN set the same requests give 403. This establishes the inconsistency only. Whether an anonymous internet client can reach the 200 state depends on the reverse proxy in front omitting all five header names and on the operator leaving LIST_TOKEN empty; the maintained example sets a token and publishes the app through BunkerWeb 1.6.17, whose generated proxy headers are not in the repository. Effect if reachable: read-only disclosure of the whitelisted networks, plus an update of the 'last fetched' timestamp shown to the operator.

**Claimed root cause.** ips_txt (whitelister/app.py:450-453) checks the raw TCP peer against LIST_ALLOWED_NETWORKS and calls has_forwarding_headers (whitelister/security.py:277-278), a fixed list of five header names. It neither refuses a peer inside settings.trusted_proxies nor treats settings.client_ip_header as proxy metadata, so the 'direct request' decision depends on what the proxy happens to add rather than on the app's own proxy configuration.

### Source trace
1. `whitelister/app.py:447` (entrypoint, create_app.ips_txt): GET /ips.txt route, no session; the whole app is published through the ingress in the example (REVERSE_PROXY_URL=/), so a relayed request arrives from the trusted proxy's address.
2. `whitelister/app.py:450` (propagation, create_app.ips_txt): peer is the raw socket address (uvicorn proxy_headers=False); the trusted proxy's address is a valid peer.
3. `whitelister/security.py:278` (propagation, has_forwarding_headers): Only five fixed header names count as proof of a relayed request; trusted_proxies and client_ip_header are not inputs.
4. `whitelister/app.py:453` (propagation, create_app.ips_txt): Single 403 gate: peer parses, no listed header, peer in list_allowed_networks, token_ok (true when LIST_TOKEN is unset, line 452).
5. `whitelister/app.py:458` (sink, create_app.ips_txt): The active whitelist is returned as text/plain; line 457 also stamps list_fetched_at.

### Verified evidence
- `whitelister/app.py:453`: Gate uses the TCP peer, has_forwarding_headers, list_allowed_networks and the optional token only.
- `whitelister/security.py:278`: Fixed tuple of five lowercase header names.
- `whitelister/app.py:173`: client_ip resolves the same request via resolve_client_ip with trusted_proxies and client_ip_header, so the two decisions can disagree (observed: /login shows 198.51.100.9 while /ips.txt answers 200).
- `whitelister/config.py:232`: LIST_ALLOWED_NETWORKS defaults to all private, loopback and ULA ranges (config.py:18-25), which normally contain the reverse proxy.
- `whitelister/config.py:214`: LIST_TOKEN is optional; empty means no token.
- `whitelister/config.py:212`: CLIENT_IP_HEADER lets the operator name a custom client-address header that /ips.txt does not treat as a forwarding header.
- `.env.example:24`: Example LIST_ALLOWED_NETWORKS=10.20.30.0/24 contains the ingress 10.20.30.2 named in TRUSTED_PROXIES (line 15); line 27 ships a token placeholder that config rejects, so the example deployment has a token and is not affected as shipped.
- `docker-compose.example.yml:40`: REVERSE_PROXY_URL=/ publishes every path, /ips.txt included, through BunkerWeb at 10.20.30.2 (line 53).
- `README.md:70`: Documented design: any forwarding header means 'came through a proxy'; this presumes the proxy always adds one of the five names.
- `tests/test_app.py:356`: Tests cover XFF/Forwarded refusal, outsider refusal and the token; none covers a TRUSTED_PROXIES peer without a listed header or a CLIENT_IP_HEADER-only request.

### Exact blockers
- The request headers the deployed reverse proxy adds are not source-visible. The path is live only if the proxy relays a request without X-Forwarded-For, Forwarded, X-Real-IP, X-Forwarded-Host and X-Forwarded-Proto. BunkerWeb 1.6.17's generated reverse-proxy configuration (and any REVERSE_PROXY_HEADERS or CDN customisation) is not in the repository and may not be fetched or run here; a stock nginx-style reverse proxy usually adds at least one of these names, which would close the path.
- The path also needs LIST_TOKEN unset in the running deployment and the proxy address inside LIST_ALLOWED_NETWORKS. Both are deployment facts; the maintained example sets a token.

### Bounded local plan
Done by v3-8 in the sandbox (scratch check-v38-cf.json, check-v38-default.json, check-v38-token.json; not promoted, re-run to reproduce): create_app(load_settings()) with dummy secrets, TRUSTED_PROXIES=10.20.30.2/32, LIST_ALLOWED_NETWORKS=10.20.30.0/24, LIST_TOKEN unset, httpx.ASGITransport client=(10.20.30.2, port). GET /ips.txt with no header or only CF-Connecting-IP returns 200; with any of the five listed names 403; peer 203.0.113.9 403; LIST_TOKEN set 403. A regression test for the fix should expect 403 for any request whose peer is inside TRUSTED_PROXIES or that carries the configured CLIENT_IP_HEADER. Nothing further can be learned locally about the real proxy.

### Owner-observed deployment plan
Owner only, on their own stack, read-only: (1) check whether LIST_TOKEN is non-empty in the running container; if it is, the path is closed. (2) From outside, request https://<public host>/ips.txt without a token and note the status; 403 is expected. (3) Inspect the BunkerWeb-generated server block for the whitelister service (and REVERSE_PROXY_HEADERS / CDN settings) and confirm that at least one of X-Forwarded-For, X-Real-IP, X-Forwarded-Proto, X-Forwarded-Host or Forwarded is set on every proxied request. A 200 in (2) confirms the finding. Source fix regardless: in ips_txt refuse peers inside settings.trusted_proxies and treat settings.client_ip_header as a forwarding header.

# Owner-observed notes from the coverage critics (not findings)

## Invitation token in reverse-proxy logs (out-of-scope unit)

Whether BunkerWeb writes the request URI of `/i/<token>` to its access log is a deployment fact. The app itself runs uvicorn with the access log off. An owner can check the BunkerWeb log format; anyone who can read those logs holds the links.

## QR code shows the link as an image

By design the invitation page draws its own link as a QR code on wide screens while the link has a slot left. The same URL is in the address bar, but a screen share or a photo of the screen hands the link on more easily. `INVITE_QR=no` turns it off; the code is hidden in print and on narrow screens.

## QR generation on the event loop

`qr_code` runs synchronously and has no explicit length cap; with `PUBLIC_URL` unset a link holder can send a Host header of about 2.3 kB and cost about 0.12 s of CPU per request (measured, linear, bounded by the QR capacity). Not a finding; capping the text length and setting `PUBLIC_URL` remove it.
