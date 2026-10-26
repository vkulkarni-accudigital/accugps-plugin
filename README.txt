AccuGPS invite-only remote test

STATUS
Prepared and tested with synthetic accounts. Not deployed or verified in the
real ChatGPT/Claude remote clients yet. This is a scheduled colleague pilot,
not a production connector or directory listing.

UPLOAD ONLY THE PREPARED BUNDLE
From the project folder, run:
  .\.venv\Scripts\python.exe .\prepare_remote_pilot.py
Upload only the contents of output/remote-pilot.zip to a new PRIVATE GitHub
repository. The bundle excludes account data, API PDFs, existing output,
local configuration, credentials, and the virtual environment. Do not upload
the whole workspace. The bundle's render.yaml is the free-plan blueprint.

FREE HOSTING
Create/sign in to Render. Use a workspace without a payment method for this
test; added payment methods can allow bandwidth/build overage charges even
when compute is Free. Connect only the new private repository. Create a
Blueprint from render.yaml, verify the Web Service plan is Free, and do not
enable paid databases, disks, plans, or upgrades. The service uses one process
and Render's automatic HTTPS URL. Its Docker image runs as an unprivileged user.
Render provides RENDER_EXTERNAL_URL; the app uses that exact origin. No custom
domain is needed. The Docker build still needs to be verified on Render.

CONFIGURATION (ENTER ON YOUR OWN COMPUTER / RENDER, NOT IN CHAT)
PILOT_ACCOUNT_EMAILS: comma-separated exact AccuGPS test account email(s),
maximum 10. Two people may use the same account for this pilot. This is an
account allowlist, not proof that two users are different people.

Generate a random invite locally, retaining it privately, and its SHA-256 hash:
  .\.venv\Scripts\python.exe -c "import secrets,hashlib;code=secrets.token_urlsafe(32);print('Invite code (share privately):',code);print('PILOT_INVITE_SHA256:',hashlib.sha256(code.encode()).hexdigest())"
PILOT_INVITE_SHA256: paste only the hash into Render's environment variables.
Give the original invite code to your colleague privately. Each user enters it
on the hosted sign-in page alongside the test account email/password. Don't
paste passwords, invites, tokens, or callback links into AI chats or screenshots.

CLIENTS AND CALLBACKS
The pilot exposes /mcp over Streamable HTTP and publishes OAuth discovery.
It advertises restricted dynamic registration (DCR): one exact configured
HTTPS callback per request, public client authentication ('none'), S256 PKCE,
authorization_code and refresh_token grants. Client IDs are stable across
restarts; live connections are not. It does not fetch URLs supplied by clients.

Default exact allowlist:
  https://claude.ai/api/mcp/auth_callback
  https://chatgpt.com/connector_platform_oauth_redirect

The callback's provider label is not cryptographic proof of client identity.
Access requires sign-in, invite, browser-bound consent and code verifier.
No client secret or AI API key is needed for the public-client DCR test.
CIMD and signed client assertions are not implemented; choose DCR when offered.
ChatGPT's stable redirect requires the implemented issuer-identification flow.
If either app displays a different callback, copy its exact value from its
connector management page. Update PILOT_CALLBACKS_JSON as an explicit JSON
map from reviewed HTTPS callbacks to labels. Never allow wildcard redirects,
arbitrary registrations, or arbitrary domains just to make an error disappear.

DEPLOYMENT CHECK BEFORE SHARING
Open the Render URL: it should show 'AccuGPS private connection test'.
Check /.well-known/oauth-authorization-server: all URLs must use that same
HTTPS origin, issuer-identification must be true, and S256 must be advertised.
Check /.well-known/oauth-protected-resource/mcp: the resource must be the
same origin plus /mcp and the issuer must match exactly (including slashes).
Unauthenticated /mcp requests must receive HTTP 401 with resource metadata.
Do not enter real credentials if HTTPS, hostname, or discovery checks fail.

CLAUDE TEST
Settings > Connectors > Add custom connector; use the deployed HTTPS /mcp URL.
Leave optional OAuth client fields blank for DCR. Start sign-in from Claude,
enter the test account and invite in the browser, approve ONE chosen device.
Ask: 'Use AccuGPS to list my authorized vehicles. Show only ID and alias.'
Then ask for that device's latest location with timestamp/freshness, and trips
and alerts for the last 24 hours. Inspect which AccuGPS tools were invoked.

CHATGPT TEST
Use the custom MCP app/plugin creation screen available in the account/workspace
(developer mode if required). Add the same deployed HTTPS /mcp URL, select OAuth
and DCR when offered, and complete a fresh sign-in and selected-device approval.
An existing subscription does not by itself guarantee access to that creation
screen; check actual account/workspace features first. Repeat the same prompts.
Actual UI wording and callback URLs may vary; use the official settings shown.

ISOLATION AND DISCONNECT
Use separate browser profiles for independently manageable connections, even
with the same AccuGPS email. In each profile open the deployed /connections URL.
Disconnect just ONE connection. New tool requests through it must be denied
or trigger fresh authorization; the other connection must continue working.
Ask for a device that wasn't selected: access must be refused. Confirm that a
second account, if tested later, cannot see the first account's unshared devices.
Removing an app in an AI client isn't the same as this server-side disconnect;
verify server-side revocation explicitly. A result already returned or copied
into an AI conversation cannot be withdrawn by disconnecting.

SECURITY AND LIMITS
Browser cookies are Secure/HttpOnly/SameSite=Lax. HTTPS, exact host/origin,
CSRF, one-use codes, PKCE, selected-device scope and upstream permissions are
checked. The authorization store retains connector token hashes. The first-party
dashboard retains its own access/refresh tokens in server memory only, never in
browser storage or page URLs. AccuGPS access tokens and account clients remain
in memory. Passwords are briefly handled
by the gateway to call the fixed AccuGPS HTTPS login API; no password file is
created. This is not upstream AccuGPS OAuth/SSO. Render terminates TLS and
therefore is part of the trusted processing path. GPT/Claude receive requested
telemetry, not the login credentials. Their chat retention rules still apply.

Access tokens last up to 15 minutes; rotating refresh tokens cannot extend the
original 1-hour approval. Reuse of a spent refresh token revokes that connection.
Disconnect revokes the grant and its codes, access and refresh tokens. Renewals
do not broaden selected devices. Every data read rechecks current device access.

Sign-in is globally bounded (20 upstream attempts/minute, 5 per pending flow);
registration has body/field limits and a 20/minute cap. There is no paid WAF,
durable abuse tracking or independent security audit. Keep the invite private
and the pilot small. Core synchronous reads serialize in this single process.

Free Render services sleep after 15 idle minutes and can restart at any time.
Restart/sleep clears every connection. Users must sign in again; no database
is provisioned. Upstream rate limits/timeouts can still delay telemetry queries.
The process trusts proxy headers ONLY behind Render's service ingress; this
launch command must not be used on an arbitrary directly exposed VM.

App access logging is disabled; infrastructure logs/metrics and provider-side
data handling still need review. Never enable request-body or token debug logs.
If account data should not be processed by Render or an AI provider, use
synthetic data or stay with the local test until those choices are approved.
At the end of the pilot disconnect grants and suspend/delete the Render service.

CAMERA METADATA UPDATE
Three additional read-only tools are available:
  get_camera_status(device_id)
  get_camera_recordings(device_id, hours=1, storage="cloud", channel=null)
  check_camera_channels(device_id, channels=[1,2,3], hours=1)

Camera access requires a NEW connection with the optional camera-metadata
checkbox explicitly selected on the device consent page. Existing grants and
refresh tokens never gain camera permission implicitly. Recordings are queried
for selected devices only, with upstream inventory access rechecked each time.
The desktop adapter also forwards these tools; the legacy login bridge does not.

Camera status reports recorder online/offline and ignition; it has no documented
source status timestamp. It does not establish GPS freshness or individual lens
health. Recording metadata contains only channel, timestamps, duration and size.
All playback URLs and arbitrary upstream fields are stripped. This update never
starts live streams, downloads media, invokes playback or requests video uploads.

Use get_camera_recordings with storage="cloud" to discover channels represented
in cloud uploads; cloud uploads do not establish the full installed/recorded set.
For on-device recordings, use storage="device" and an explicit channel. Allowed
channel inputs are bounded to 1-16, not a claim about the device's supported slots.
Windows are 1-24 hours; returned rows are bounded to 500. Counts cover valid
matching rows in the API response, not an independently verified complete archive.

check_camera_channels accepts 1-3 distinct probe numbers per call and queries
them sequentially against one fixed window. A typical three-channel probe is NOT
an installation declaration. It never assumes the auxiliary camera is channel 4.
Offline/unknown recorder status skips device recording queries; a request failure
stops further probes. Empty, zero-size, malformed and inaccessible recordings
are distinguished, and never automatically labeled hardware failures. Image
quality and actual camera placement still require separately authorized viewing.

The pilot now rejects overlapping MCP POST requests with HTTP 429 / Retry-After
instead of queuing a whole fleet batch. Query devices one at a time. Authorization
store access is moved off the event loop so a slow read does not block health
responses. In-flight reads still serialize and disconnect may wait for a running
read; this is not a production concurrency architecture or a security audit.

Release verification: deploy the new commit manually on Render, reconnect using
the demo account and invite, select the intended units and camera-metadata box,
then refresh tools in the AI client. First test status on ONE known active camera,
then cloud metadata, then a short on-device channel probe. The documented camera
recorder status endpoint has returned online/ignition status in a live check.
Cloud and on-device recording requests failed in that check and remain under
investigation; a permission error, unsupported endpoint or timeout is an API/access
finding, not a broken camera.

Synthetic validation: 59 Python tests pass. To reproduce in a virtual environment with
the locked dependencies installed, run: python -m unittest discover -s tests
The included fixtures contain synthetic accounts only. Tests cover camera opt-in,
selected-device restrictions, URL redaction, malformed/empty data, offline status,
bounded probes, MCP transport calls and health responsiveness during contention.

PRIVATE MONITORING DASHBOARD
After manually deploying this update, open https://<your-host>/dashboard.
No new environment variables, paid service or AI subscription are required.
Each viewer signs in through the existing invite, allowed account, selected-device
and optional camera-metadata consent flow. Use account credentials privately in
the browser. Do not send credentials, invite codes or tokens in chat.

Select the intended devices (the commissioning pilot has nine). After the first
GPS cycle finishes, tick Camera unit for each actual camera recorder and click
Save camera selection. Do not mark OBD trackers as camera recorders. Hardware
type is team configuration, not inferred from aliases or account list membership.
The dashboard checks at most the first 50 currently authorized selected devices;
the UI warns if more than 50 were approved. Use a smaller selection for this pilot.

GPS timestamps, coordinate bounds validity, recorder status and ignition are
collected sequentially. Source coordinates and addresses are discarded from the
dashboard projection. GPS age is not end-to-end transmission latency: there is
no server-receive timestamp. A parked/sleeping unit can have an old fix. Recorder
source timestamps are unavailable. Do not certify zero GPS delay or lens health.

The browser requests the current snapshot every 30 seconds while visible. Each
snapshot requires a valid session and a current upstream inventory access check;
if that check fails, observations are withheld. Telemetry collection is shared
only by the same account subject, selected-device set, camera consent and camera
configuration. Another account or permission scope never shares that collection.
Current upstream access is also checked within every telemetry query.

A new cycle starts no sooner than five minutes after the preceding cycle finishes,
on the next visible-page request. It is not an exact five-minute service-level
promise: slow APIs, sequential reads, throttling, sleeps and restarts can delay it.
No collection is scheduled while pages are closed; an already-started bounded
cycle may finish. Checks also share the existing synchronous authorization lock
with MCP reads. This is a small pilot, not a production monitoring architecture.

The detail view shows the last 20 check events per unit and an optional manual
last-hour CLOUD recording metadata check, limited to one attempt per account/unit
per five minutes. It does not query on-device channels, start streams, upload
clips or retrieve footage. Empty metadata is not a camera failure. Auxiliary
channel mapping and image quality remain unverified. No outbound notifications
or durable historical reporting are implemented.

On API failure, the last successful GPS/recorder observation remains labeled with
its original check time and the failed attempt time. Raw exception details are
not returned. Source inventory failure or revoked/expired sign-in withholds data.
The dashboard's client is separately restricted to location, recorder status and
cloud recording metadata; its session cannot query trips, alerts or fuel data.

Views share AccuGPS account identity; this does NOT implement individual employee
identity, roles, invitations or a team audit trail. Anyone using the same account
with the pilot invite can request that account's devices and explicitly approve
them. Never share a browser session/token. Dashboard disconnect revokes its own
grant, leaving separately approved GPT/Claude grants independent.

Sessions last at most one hour. Tokens, collections and history live only in
memory, clear on restart, and are not stored in Git or browser localStorage.
There is no durable credential vault, unattended worker or independent security
audit. Keep testing limited to approved accounts/devices. Closing the browser is
not a substitute for Disconnect; a session expires automatically at its limit.

UI checks (Node.js, no packages required):
  python -c "from pathlib import Path; from dashboard_view import SCRIPT; Path('dashboard-app.js').write_text(SCRIPT, encoding='utf-8')"
  node --check dashboard-app.js
  node tests/test_dashboard_view.cjs dashboard-app.js
The generated file is a public static script, with no account data or secrets;
keep it out of commits. Isolated rendering tests do not replace browser/device QA.

REFERENCE DOCUMENTATION CHECKED
https://render.com/docs/free
https://render.com/docs/web-services
https://developers.openai.com/plugins/build/auth
https://help.openai.com/en/articles/12584461-developer-mode-and-mcp-apps-in-chatgpt
https://support.anthropic.com/en/articles/11503834-building-custom-integrations-via-remote-mcp-servers
