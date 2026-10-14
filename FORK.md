# WhatsApp MCP integration fork

Repository: https://github.com/skosovsky/whatsmeow, branch `codex/wa-mcp`.
Upstream base: `35ae40906e74` (the application's previously accepted version).
Original source/license notices are retained. Git history records the patch stack:

- PR #1226, original `f1c90c646355ceb4941dfdc246607e8462d81c25`: per-request
  disconnect retry control for WhatsApp and Facebook, with original author credit.
- Upstream `f331563`: split-frame length calculation fix.
- PR #1284, original `3947449`: cancellable synchronous Noise writes.
- Application-specific authority hooks, response proofs, receipt retry policy,
  and opt-in synthetic native fixtures, carried forward from the local fork.

Links: https://github.com/tulir/whatsmeow/pull/1226,
https://github.com/tulir/whatsmeow/pull/1284,
https://github.com/tulir/whatsmeow/issues/1285.

The application pins an immutable pseudo-version of this fork. Current upstream
main changes the blocklist API/protocol; rebasing beyond the accepted base needs
its own application contract migration. The upstream socket PR remains minimal
and targets main independently of this integration branch.

The PR #1226 internal socket interface remains available to its tests. Guarded
sends require the concrete Noise socket and fail closed on other implementations;
unmatched mutation results likewise require original authenticated Noise proof.

Current runtime changes: socket/noisesocket.go, socket/framesocket.go, send.go,
client.go, retry.go, request.go, upload.go and mediaconn.go.
Noise writes acquire a cancellable per-socket queue, stay synchronous through
actual websocket Write return, and pass the original caller context to Write.
Cancellation cannot return while a created physical writer remains active. Any
error after encryption closes the ambiguous Noise connection without another
close control frame; the counter/session cannot be reused after uncertain bytes.
A queued cancelled request creates no writer and does not advance the counter.
Writer panic returns a fixed error and closes the ambiguous session. Tests use
the actual coder websocket/Noise/Frame stack over a controlled network body and
a local websocket receiver. They observe actual Write exit and decrypt frames.

Message SendRequestExtra.NoRetry stops disconnect retryFrame and skips the
in-memory/durable retry payload cache. DisableRetryReceipts (default false)
refuses incoming retry requests before payload lookup, including old persisted
payloads and custom callbacks. The MCP production client sets it before connect;
its common message adapter forces NoRetry on copied original options. This
also disables receipt retries for SDK housekeeping messages in that client.
Actual SendMessage/local websocket tests decrypt literal Unicode nodes and
observe two frames in the stock baseline versus one for NoRetry. Retry-handler
tests poison downstream stores/callbacks for cached WA/FB and fresh client cases.

BeforeWrite hooks on SendRequestExtra/infoQuery are now routed to Noise after
writer queue admission and before encryption. They force NoRetry and are
selected by exact request node tag/ID; preparatory nodes of other tags do not
consume message authority. A per-invocation atomic guard refuses a second
attempt. Denial/panic is redacted and leaves the untouched counter/session
reusable; original context cancellation is checked before and after the hook.
Tests cover queued denial/cancellation, panic, counter/session preservation,
concurrent attempts and actual SendMessage/sendIQ physical local frames.

Application operation/audit/admission authority closures and integrated public
physical entitlement proof remain required by
the application repository's `docs/native-transport-contract.md`. A single method-return test does not
prove all of that contract. Application go test ./... skips dependency tests; run its
explicit message/socket tests and race/vet gates in addition to root verification.
No personal WhatsApp action is authorized by this fork or its tests.

The application's Makefile fork-test/fork-race/fork-vet targets explicitly test
this pinned dependency. Its manifest checker verifies the remote replacement,
immutable version and module checksum. Use Git diffs against the base above to
review the full fork delta; there is no duplicated source inventory. The upstream
version probe does not automatically mutate or remove the replacement.

Native public integration fixture mcp_native_test_transport.go is excluded unless
wa_mcp_native_test is explicitly enabled. It owns an ephemeral loopback websocket
with synthetic device/deterministic Noise keys; no supplied network URL or remote
session. Outgoing packets are decrypted/counted; encrypted ACK enters the native
receiver/parser/waiter. Actual queue barrier emits zero bytes and SDK waiter
admission is observed before store proof mutation. Normal production builds
contain no fixture API/transport override. Explicit tagged root integration gates
are required; ordinary nested/default tests do not prove that suite.

The explicit-tag fixture can gate the upgraded loopback HTTP body's actual Write
before underlying I/O or after underlying Write but before returning to the SDK.
The latter additionally requires owned peer decryption before cancellation.
Cancellation reaches Close independently; Close never
releases that gate. Public integration observes physical Write entry/exit,
handler/admission/audit/dispatch lease lifetime and zero complete packets on
pre-write cancellation versus one original packet on post-emission cancellation. It adds no ordinary production transport behavior.

The same explicit-tag fixture now provisions fresh sender/receiver SQLite SDK
stores for group text/reply tests. The receiver is initialized from pre-send
sender-key distribution and independently decrypts the actual observed Signal
skmsg; no message send backend replaces SDK SendMessage. The synthetic group has
only the current sender device, excluded from pairwise distribution by the real
SDK. Distribution is provisioned out of band, certificate fields are synthetic
local storage data, and neither device certificate authentication nor DM Signal
session/distribution interoperability is claimed. Native message gates are
separate from IQ gates; runtime fork inventory contains eight reviewed files.

Original message frame authority now exposes a private typed destination proof
only during the consumed native callback; captured contexts lose active proof
when it returns. Prepared text/reply verifies that actual destination against the
original authorized recipient fingerprint and exact owned PN/LID reverse mapping,
including PN-to-LID SDK translation. Request ID, single-use callback, deadline,
physical admission and NoRetry behavior remain in force. Direct explicit-tag
fixtures use real signed/one-time prekeys and pairwise Signal sessions on two
independent SQLite devices. Keys/devices/privacy data are provisioned locally;
no authenticated remote discovery, device certificate or WhatsApp interoperability
is inferred from these tests. Group and direct native cases share the Makefile
native-message gates; the fixture remains excluded from normal builds.


Opt-in UploadWithAuthority retains original SDK attachment encryption and HTTP
upload, copying the original plaintext and exposing its exact hash/byte count/type
only inside an active private proof window. Admission and media-connection IQ
guards precede preparation; the IQ uses the existing native BeforeWrite/NoRetry
path. A single-use guard precedes upload RoundTrip/dial and a final guard precedes
return of usable upload metadata. HTTP is isolated to a fresh concrete cloned
transport, HTTP/1, no keepalive reuse, redirects or rewindable body; opaque custom
RoundTrippers are refused. Dial/Read/Write calls are tracked, sealed and joined before
return on failure/cancellation. Guarded response parsing is bounded and errors
are static with no partial upload response. Ordinary Upload behavior is retained.

Synthetic TLS tests execute original Upload and inspect encrypted bytes, SHA256,
MAC and independently decrypted Unicode plaintext. They also exercise denial,
panic, cancellation, proof-window lifetime, response/redirect refusal, cold-cache
original IQ denial and controlled original HTTP writes held before/after emission
through cancellation. No real endpoint, personal account or WhatsApp/CDN
interoperability is inferred. Native application wiring, approved media send,
current recipient/policy/budget authority, UI/audit and recovery remain required.

Captured guarded contexts are refused by ordinary Upload/Reader/Newsletter entry
points before source I/O, including during an active proof window. Guarded upload
uses one private original SDK encryption path and checks its actual plaintext
digest/length/type against frozen native proof before preparation. Physical
Dial/Write faults are recorded before the join signal, so a racing HTTP response
cannot hide a writer failure or panic; tests cover pre/post-emission writer panic
and active-context bypass without Reader/Seek execution.

RoundTrip admission also rechecks live authority immediately before each created
original transport Write, using upload_write proof windows and the original
caller context. A delayed Dial cannot turn earlier admission into permission to
POST after operator/grant/clock revocation. A synthetic original TLS Dial barrier
verifies post-dial denial with zero emitted HTTP requests. Callbacks may repeat
for TLS/proxy/request writes; they must be read-only and verify the existing
attempt/budget lease, not charge a new action or read/transcode the full source
for every write.

Guarded privacy mutation: privacy_guarded.go adds SetPrivacySettingGuarded with
a required trusted BeforeWrite callback and explicit NoRetry. It sends one
selected privacy IQ set with no implicit reads or local cache update. The stock
SetPrivacySetting compatibility method still permits reconnect retry and must
not be used by the approved MCP dispatcher. Original result receipt is distinct
from a fresh selected-value snapshot. Synthetic actual Noise/websocket tests
cover all ten names, literal destination/category, successful response,
disconnect without resend, denial, panic and cancellation. Application policy,
consumed grant, operation CAS and native callback integration remain required.

Privacy execute acknowledgment now requires an empty IQ result with exactly the
original generated request ID, server JID sender and result type. Foreign sender,
substituted ID, payload and extra attributes are rejected as unusable response
evidence; no refresh or retry follows. Nested tests include these response
refusals. The explicit-tag root internal service suite additionally exercises
original privacy GET parsing, consumed grant/dispatching CAS, actual native
BeforeWrite/Noise mutation and encrypted result parsing for all ten names;
ACK/disconnect/foreign/content outcomes survive physical SQLite reopen without
another GET/set. This is internal service coverage, not public MCP policy/audit
or human issuer integration.


Guarded participant additions preserve original cached LID-to-PN and ensureTCToken
preparation. The separately added group_participants_guarded.go owns bounded targets,
checks trusted preparation around cache reads and rechecks PN/storage-LID/token bytes
before and after the physical authority callback. The original sendIQ uses NoRetry
and BeforeWrite; no upstream group.go/tctoken.go was modified. Strict correlated
result parsing retains per-target errors/invitation-required, excludes invitation
bearers and raw participant metadata. Preparation uses original local token pruning
semantics; no privacy-token issuance or remote lookup is added. Native tests use
actual Noise/Frame/local websocket SET and controlled synthetic cache providers;
these providers do not prove SQLite SDK-store or remote WhatsApp interoperability.
Application original ledger/grant/audit/lease integration remains required.

Group creation guarded addition (`group_creation_guarded.go`): normal-group-only
frozen creator/name/target data, owned cached participant/token preparation,
current paired-actor and snapshot checks surrounding physical frame authority,
one explicit NoRetry w:g2 creation IQ, strict bounded same-attempt typed receipt
without privacy/invitation bearer or raw group node. Original upstream group.go
is unchanged and its direct CreateGroup remains outside the hardened app policy.
The dedicated tests cover actual outbound Noise/FrameSocket and a synthetic SDK
response waiter plus parser checks; they do not prove native inbound parser,
remote interoperability or the public human-approved app pipeline. New files are
in the exact reviewed inventory and format gates. Broader native queued/physical/
late-ACK and integrated application acceptance remain required.

OriginalGroupCreationRequestID is a private-frame correlation accessor: the
creation method binds original generated ID to its actual consumed/active frame
authority. Background/preparation/captured/another-authority contexts cannot read
it; it provides neither emission nor ACK permission. Native outbound tests match
the accessor ID against the encrypted peer and test stale/same-ID other contexts.
The app persists a scoped original attempt journal before Write and repeats exact
journal and full independent authority checks. Journal failure refuses emission.
No raw node/bearer/result is exposed by this accessor, and the SDK still uses its
original strict receipt parser and NoRetry. Post-restart response handling remains
an independent required app/SDK integration, not proven by retaining an ID.

Authenticated unmatched creation response groundwork: NoiseSocket mints a private
active, exact-byte, same-socket, single-use receive context proof only after AEAD
success. Client.handleFrame consumes it before decoding; dangerous direct frame
and response-waiter APIs cannot mint GroupCreationResponse. Active waiters retain
normal handling without duplicate events. Eligible unmatched group-result events
own at most 32 KiB and expose only private correlation and strict typed parsing
against the original frozen request/current SDK/actor/socket. Formatting is
redacted; no raw node or bearer is exposed. The app does not yet handle this event
or persist a reconciliation transition. This does not promise upstream replay
across reconnect. Test-only owned peer delivery/close exercise actual encrypted
inbound and native disconnect without any new client IQ/message.

Guarded blocklist read addition (`blocklist_guarded.go`): original NoRetry blocklist
IQ GET with mandatory trusted physical frame authority and strict correlated
result/list/item parsing. Reject the entire malformed or duplicated list; return
only owned PN/LID identities and discard opaque dhash. This read sends no SET or
user-info discovery, changes no blocklist event/cache handling and interprets no
mutation ACK. The legacy upstream
user.go parser remains unchanged. Pure parser tests live in the fork; encrypted
loopback tests and private client prepare/revalidate integration live in root
internal/client/native_blocklist_guarded_test.go under wa_mcp_native_test. They
prove local native behavior, not remote WhatsApp interoperability or human approval.

The same file now adds UpdateBlocklistGuarded: frozen actor/target PN/LID/action,
self exclusion, reciprocal cached mapping checks, mandatory preparation/final
callbacks and one original NoRetry IQ SET. No legacy UpdateBlocklist/GetUserInfo
fallback or auxiliary network lookup. Physical guards recheck actor/mapping after
the application callback. OriginalBlockActionRequestID exposes correlation only
inside the consumed SET frame guard, refusing stale/other-action contexts.
The strict original result must contain the selected desired state; opaque SDK
evidence binds instance, request ID and complete request, with redacted formatting
and no full-list projection. It grants no application receipt/dispatch authority.
Root native_block_action_guarded_test.go proves exact SET, state/shape failures,
callback/actor/mapping/cancellation denial, real writer-queue revocation, no retry,
waiter cleanup and DTO/evidence refusal. Durable journal, late ACK reconciliation
and host approval/public executor integration remain separate unfinished work.

request.go sendIQ now removes only the original response channel on return. Match
the captured channel identity before deletion and do not close it: an inbound
receiver may already own it outside the map lock. Cancellation/IQ timeout no longer
retain that original waiter, and cleanup cannot delete a newer same-ID attempt.
The private async helper exposes its owned bidirectional channel only internally
for exact comparison; public async signatures are unchanged. Encrypted wrong-ID
and withheld-response tests first reproduced leakage, then passed after cleanup.


Late block response routing now shares one authenticated-frame consumption with
creation routing in client.go, after the original waiter gets first refusal.
blocklist_guarded.go adds private cloned decoded envelope/socket correlation and
strict bounded list parsing; a derived result retains socket identity and rejects
current socket replacement or disconnect. The envelope does not recover original
PN/LID/action: application journal validation remains mandatory before ACK CAS.
The added blocklist_response_native_test.go is test-tagged only and exercises two
real connected encrypted sockets under the actual identity lock. Run this test
from the root module (fixture dependencies):
`go test -race -tags=wa_mcp_native_test go.mau.fi/whatsmeow -run '^TestNativeBlockResponseSocketReplacement' -count=3`.
Root native block response tests also cover actual timeout/late delivery, raw
handler refusal, complete malformed envelopes, matched waiter priority and original
journal unknown-to-ACK with no resend. Existing creation routing regression and
complete fork races remain separate evidence. Eight original runtime files remain
the reviewed inventory; the new file adds tests only. Production block executor,
reconciliation worker and host/public approval integration remain unfinished.


Guarded group leave adds group_leave_guarded.go without changing the upstream
LeaveGroup behavior. The reviewed client.go delta supplies the exact selected
NoiseSocket in private physical-frame context and records only registered original
leave ACKs at the authenticated decrypted boundary, before waiter routing. Raw
DangerousInternals.ReceiveResponse/HandleFrame cannot create opaque evidence.
Frozen own PN/LID participant, original device pointer/full AD identity, IQ ID and
socket bind the result; original active callback correlation is not authority.
One NoRetry w:g2 SET targets g.us with the exact leave/group ID. Timeout,
cancellation, callback refusal, malformed response and disconnect never resend.

The added pure guarded tests and root tagged native tests cover closed shape,
PN/LID, callback/actor/device drift, literal encrypted SET, writer revocation, raw
injection and opaque proof serialization/refusal. The tagged fork test
TestNativeGroupLeaveProofCurrentSocketReplacement checks two actual connected
sockets and real SDK identity-lock contention. Run tagged fixture-dependent tests
from the root module. Application durable journal, consumed-grant verification,
ACK CAS and public leave execution are implemented separately in the application.
Late application reconciliation/subscription remains unfinished. Unmatched empty
IQ candidates never acknowledge an application operation on their own.


Group leave late response envelope: unmatched authenticated empty IQ results
from g.us can create an opaque GroupLeaveResponse bounded at 4096 decoded bytes.
The shared mutation boundary consumes original Noise frame authority once; raw
HandleFrame/ReceiveResponse cannot create the envelope. Result binds the expected
original journal request and repeatedly checks captured SDK/device/full AD ID/LID
and current original socket. No SQL, SDK request, policy or grant is created.
Zero/JSON objects cannot recreate its private fields.

If original ACK capture wins a race with waiter removal, handleFrame carries that
confirmed original socket origin directly into the unmatched leave envelope; it
does not consume authenticated frame authority twice. Tagged native coverage
uses an actual retained registered attempt from one timed-out emitted encrypted
SET to model that cleanup interval. Socket/device drift, malformed frames, raw
injection and direct primary original proof checks remain covered. Run tagged
SDK tests from the root module, with its native fixture dependencies.

Message revoke original response: additive `message_revoke_guarded.go` accepts
only typed canonical paired identity, exact cached-target tuple and a distinct
bounded attempt ID, builds REVOKE internally and forces NoRetry/physical guard.
Deadline is required (<=30s); active attempts are bounded at 64 and cleaned on
all exits. No arbitrary protobuf or response can establish its opaque result.
The existing client decoded-frame boundary captures message ACK origin before
waiter routing, consuming the original Noise proof once for a registered passed
attempt. It checks exact id/class/wire chat/positive canonical decimal timestamp,
empty content and only optional bounded phash. Result verification repeats the
original SDK/device/full ID/LID/current connected socket and immutable request.
Raw waiter/HandleFrame/JSON/zero proofs cannot create origin. Physical callback
checks local state only; no nested network write under the Noise gate.

Tagged root native tests use independent Noise and Signal decryption on real
synthetic SDK SQLite devices for own/foreign PN/LID target sender keys. They
verify original ACK, optional phash, malformed/raw ACK, callback denial/panic and
request/SDK/device/socket substitutions. This is SDK group proof only: application
ledger ACK persistence, native direct revoke, public prepared execution and late
ACK/reconnect reconciliation remain pending. No production WhatsApp action was
performed. The eight original changed runtime files stay the same; this wrapper
and its semantic tests are reviewed additive files in the fork inventory.

Original revoke journal correlation: only the active physical message callback
can read its immutable typed request and a SDK-minted 256-bit attempt nonce.
Received and original source deadline must match and both contexts remain live;
released/detached/shortened-deadline context cannot establish correlation.
VerifyOriginalAttempt binds the opaque original result to this exact private
nonce, in addition to SDK/device/full identity/current socket/request checks.
An identical public request tuple from another genuine SDK send has a different
nonce and cannot replace application journal origin. The nonce is not accepted
as a request field and alone grants no receipt authority. Application owned
journal and ACK CAS are implemented outside this SDK wrapper.
