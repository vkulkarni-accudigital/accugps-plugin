"""In-memory authorization foundation; not a standalone OAuth server.

No password handling, storage on disk, HTTP routes or client registration.
Account clients must already be authenticated before a grant can be approved.
An HTTP/OAuth adapter must validate browser consent/CSRF before calling approve.
"""

from dataclasses import dataclass, field
import base64
import hashlib
import hmac
import re
import secrets
import threading
import time
from urllib.parse import urlsplit

from accugps_tools import ScopedClient


class AuthorizationDenied(ValueError):
    pass


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def pkce_challenge(verifier):
    if not isinstance(verifier, str) or not re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", verifier):
        raise AuthorizationDenied("Invalid PKCE verifier")
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).decode("ascii").rstrip("=")


@dataclass(frozen=True)
class ApprovedGrant:
    grant_id: str
    client_id: str
    subject: str
    audience: str
    expires_at: float
    client: ScopedClient = field(repr=False, compare=False)
    camera_metadata: bool = False


@dataclass(frozen=True)
class PendingCode:
    grant_id: str
    redirect_uri: str
    challenge: str
    expires_at: float


@dataclass(frozen=True)
class IssuedToken:
    grant_id: str
    expires_at: float


class AuthorizationStore:
    """Small local-test store: opaque tokens, selected devices, explicit lifetimes.

    The browser adapter owns identity proof and explicit per-client consent.
    Registry and audience come from trusted deployment configuration, not requests.
    Raw codes/tokens are returned once; only their hashes are retained here.
    """

    def __init__(self, audience, clients, clock=time.time, *, allow_loopback=False):
        self._validate_url(audience, allow_loopback)
        self.audience = audience
        self.clients = {}
        for client_id, redirects in clients.items():
            if not client_id or not redirects:
                raise ValueError("Each client needs an ID and exact registered redirect URIs")
            for uri in redirects:
                self._validate_url(uri, allow_loopback)
            self.clients[client_id] = frozenset(redirects)
        self.clock = clock
        # Optional trusted server-side restrictions for first-party clients.
        self.client_read_kinds = {}
        self._grants, self._codes, self._tokens, self._refresh = {}, {}, {}, {}
        self._spent_refresh = {}
        self._lock = threading.RLock()

    @staticmethod
    def _validate_url(value, allow_loopback):
        parsed = urlsplit(value)
        local_http = allow_loopback and parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
        if (not parsed.hostname or parsed.username or parsed.password or parsed.fragment
                or not (parsed.scheme == "https" or local_http)):
            raise ValueError("HTTPS URLs are required; loopback HTTP is an explicit development exception")

    def _purge(self):
        now = self.clock()
        expired = {key for key, grant in self._grants.items() if grant.expires_at <= now}
        for key in expired:
            self._grants.pop(key, None)
        self._codes = {key: code for key, code in self._codes.items()
                       if code.expires_at > now and code.grant_id in self._grants}
        self._tokens = {key: token for key, token in self._tokens.items()
                        if token.expires_at > now and token.grant_id in self._grants}
        self._refresh = {key: token for key, token in self._refresh.items()
                         if token.expires_at > now and token.grant_id in self._grants}
        self._spent_refresh = {key: token for key, token in self._spent_refresh.items()
                               if token.expires_at > now and token.grant_id in self._grants}

    def approve(self, *, client_id, redirect_uri, subject, account_client,
                device_ids, challenge, audience, grant_seconds=3600, camera_metadata=False):
        """Create a grant after the browser adapter verifies sign-in and consent."""
        if client_id not in self.clients or redirect_uri not in self.clients[client_id]:
            raise AuthorizationDenied("Unregistered client or redirect URI")
        if audience != self.audience:
            raise AuthorizationDenied("Wrong resource audience")
        if not isinstance(subject, str) or not subject:
            raise AuthorizationDenied("Verified account subject required")
        if getattr(account_client, "scope", None) != "authenticated_accugps_account":
            raise AuthorizationDenied("Authenticated account client required")
        if not isinstance(challenge, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", challenge):
            raise AuthorizationDenied("S256 PKCE challenge required")
        if isinstance(grant_seconds, bool) or not isinstance(grant_seconds, int) or not 1 <= grant_seconds <= 3600:
            raise AuthorizationDenied("Grant lifetime must be 1-3600 seconds")
        if type(camera_metadata) is not bool:
            raise AuthorizationDenied("Explicit camera metadata consent required")
        selected = frozenset(device_ids)
        current = {row["device_id"] for row in account_client.list_devices()}
        if not selected or not selected.issubset(current):
            raise AuthorizationDenied("Select only devices currently authorized for this account")
        with self._lock:
            self._purge()
            now = self.clock()
            grant_id = secrets.token_urlsafe(32)
            self._grants[grant_id] = ApprovedGrant(grant_id, client_id, subject, audience,
                                                  now + grant_seconds, ScopedClient(account_client, selected), camera_metadata)
            code = secrets.token_urlsafe(32)
            self._codes[digest(code)] = PendingCode(grant_id, redirect_uri, challenge, min(now + 60, now + grant_seconds))
            return grant_id, code

    def exchange(self, *, code, client_id, redirect_uri, verifier, audience):
        challenge = pkce_challenge(verifier)
        with self._lock:
            self._purge()
            pending = self._codes.get(digest(code))
            grant = self._grants.get(pending.grant_id) if pending else None
            if (not pending or not grant or grant.client_id != client_id
                    or pending.redirect_uri != redirect_uri or audience != grant.audience
                    or not hmac.compare_digest(pending.challenge, challenge)):
                raise AuthorizationDenied("Invalid or expired authorization code")
            # Only a successful exchange consumes the code. Lock prevents replay races.
            del self._codes[digest(code)]
            token = secrets.token_urlsafe(32)
            expires = min(self.clock() + 900, grant.expires_at)
            self._tokens[digest(token)] = IssuedToken(grant.grant_id, expires)
            return token, expires

    def resolve(self, token, *, audience, client_id=None):
        with self._lock:
            self._purge()
            issued = self._tokens.get(digest(token))
            grant = self._grants.get(issued.grant_id) if issued else None
            if not grant or audience != grant.audience or (client_id is not None and client_id != grant.client_id):
                raise AuthorizationDenied("Invalid, expired or revoked connector token")
            return grant

    def issue_refresh(self, token, *, audience):
        """Optional remote-pilot renewal; never extends the approved grant lifetime."""
        with self._lock:
            grant = self.resolve(token, audience=audience)
            refresh = secrets.token_urlsafe(32)
            self._refresh[digest(refresh)] = IssuedToken(grant.grant_id, grant.expires_at)
            return refresh

    def renew(self, *, refresh_token, client_id, audience):
        with self._lock:
            self._purge()
            issued = self._refresh.get(digest(refresh_token))
            if issued is None:
                spent = self._spent_refresh.get(digest(refresh_token))
                family = self._grants.get(spent.grant_id) if spent else None
                if family and family.client_id == client_id and family.audience == audience:
                    self.disconnect(subject=family.subject, grant_id=family.grant_id)
                raise AuthorizationDenied("Invalid, expired or revoked refresh token")
            grant = self._grants.get(issued.grant_id) if issued else None
            if not grant or grant.client_id != client_id or grant.audience != audience:
                raise AuthorizationDenied("Invalid, expired or revoked refresh token")
            del self._refresh[digest(refresh_token)]
            self._spent_refresh[digest(refresh_token)] = issued
            token, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            expires = min(self.clock() + 900, grant.expires_at)
            self._tokens[digest(token)] = IssuedToken(grant.grant_id, expires)
            self._refresh[digest(refresh)] = IssuedToken(grant.grant_id, grant.expires_at)
            return token, refresh, expires

    def revoke_token(self, token, *, audience, client_id):
        with self._lock:
            self._purge()
            issued = self._tokens.get(digest(token)) or self._refresh.get(digest(token)) or self._spent_refresh.get(digest(token))
            grant = self._grants.get(issued.grant_id) if issued else None
            if grant and grant.audience == audience and grant.client_id == client_id:
                self.disconnect(subject=grant.subject, grant_id=grant.grant_id)

    def query(self, token, *, audience, device_id, kind, hours=24, end_time=None, **options):
        # Keep disconnect atomic with reads in this small synchronous prototype.
        with self._lock:
            grant = self.resolve(token, audience=audience)
            allowed = self.client_read_kinds.get(grant.client_id)
            if allowed is not None and kind not in allowed:
                raise AuthorizationDenied("This client is not approved for that data type")
            if kind.startswith("camera-") and not grant.camera_metadata:
                raise AuthorizationDenied("Reconnect and explicitly approve camera status and recording metadata")
            return grant.client.query(device_id, kind, hours, end_time, **options)

    def token_info(self, token, *, audience):
        with self._lock:
            grant = self.resolve(token, audience=audience)
            return grant, self._tokens[digest(token)].expires_at

    def disconnect(self, *, subject, grant_id):
        with self._lock:
            self._purge()
            grant = self._grants.get(grant_id)
            if grant is not None and grant.subject != subject:
                raise AuthorizationDenied("Cannot revoke another account's connection")
            self._grants.pop(grant_id, None)
            self._purge()

    def shutdown(self):
        with self._lock:
            self._grants.clear()
            self._codes.clear()
            self._tokens.clear()
            self._refresh.clear()
            self._spent_refresh.clear()
