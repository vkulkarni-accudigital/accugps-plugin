import unittest
from unittest.mock import Mock

from authorization_core import AuthorizationDenied, AuthorizationStore, pkce_challenge


class AuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.now = 1000
        self.audience = "https://connector.example/mcp"
        self.redirect = "https://client.example/callback"
        self.store = AuthorizationStore(self.audience, {"claude-test": [self.redirect]}, clock=lambda: self.now)
        self.account = Mock(scope="authenticated_accugps_account")
        self.account.list_devices.return_value = [{"device_id": "car-a"}, {"device_id": "car-b"}]
        self.account.query.return_value = {"data": "synthetic"}
        self.verifier = "a" * 43

    def approve(self, **overrides):
        args = dict(client_id="claude-test", redirect_uri=self.redirect, subject="account-a",
                    account_client=self.account, device_ids=["car-a"], challenge=pkce_challenge(self.verifier), audience=self.audience)
        args.update(overrides)
        return self.store.approve(**args)

    def exchange(self, code, **overrides):
        args = dict(code=code, client_id="claude-test", redirect_uri=self.redirect, verifier=self.verifier, audience=self.audience)
        args.update(overrides)
        return self.store.exchange(**args)

    def test_success_keeps_upstream_token_private_and_limits_devices(self):
        grant_id, code = self.approve()
        token, expires = self.exchange(code)
        self.assertEqual(expires, 1900)
        self.assertNotIn(token, self.store._tokens)
        self.assertNotIn(code, self.store._codes)
        grant = self.store.resolve(token, audience=self.audience)
        self.assertEqual(grant.grant_id, grant_id)
        self.assertNotIn("client=", repr(grant))
        self.assertEqual(self.store.query(token, audience=self.audience, device_id="car-a", kind="location"), {"data": "synthetic"})
        self.account.query.reset_mock()
        with self.assertRaises(ValueError):
            self.store.query(token, audience=self.audience, device_id="car-b", kind="location")
        self.account.query.assert_not_called()

    def test_unregistered_redirect_client_resource_or_devices_denied(self):
        for override in [{"client_id": "unknown"}, {"redirect_uri": self.redirect + "/evil"},
                         {"audience": "https://other.example/mcp"}, {"device_ids": ["other-account-car"]}, {"device_ids": []}]:
            with self.subTest(override=override), self.assertRaises(AuthorizationDenied):
                self.approve(**override)

    def test_code_is_bound_to_pkce_client_redirect_and_resource_and_single_use(self):
        _, code = self.approve()
        for override in [{"verifier": "b" * 43}, {"client_id": "other"},
                         {"redirect_uri": self.redirect + "?evil=1"}, {"audience": "https://other.example/mcp"}]:
            with self.subTest(override=override), self.assertRaises(AuthorizationDenied):
                self.exchange(code, **override)
        self.exchange(code)
        with self.assertRaises(AuthorizationDenied):
            self.exchange(code)

    def test_code_and_token_expiry_and_resource_validation(self):
        _, code = self.approve()
        self.now += 61
        with self.assertRaises(AuthorizationDenied):
            self.exchange(code)
        _, code = self.approve()
        token, _ = self.exchange(code)
        with self.assertRaises(AuthorizationDenied):
            self.store.resolve(token, audience="https://other.example/mcp")
        with self.assertRaises(AuthorizationDenied):
            self.store.resolve(token, audience=self.audience, client_id="other")
        self.now += 900
        with self.assertRaises(AuthorizationDenied):
            self.store.resolve(token, audience=self.audience)

    def test_refresh_rotation_replay_and_expiry(self):
        _, code = self.approve()
        token, _ = self.exchange(code)
        refresh = self.store.issue_refresh(token, audience=self.audience)
        self.assertNotIn(refresh, self.store._refresh)
        self.now += 901
        with self.assertRaises(AuthorizationDenied):
            self.store.renew(refresh_token=refresh, client_id="other", audience=self.audience)
        new, rotated, _ = self.store.renew(refresh_token=refresh, client_id="claude-test", audience=self.audience)
        self.store.resolve(new, audience=self.audience)
        with self.assertRaises(AuthorizationDenied):
            self.store.renew(refresh_token=refresh, client_id="claude-test", audience=self.audience)
        with self.assertRaises(AuthorizationDenied):
            self.store.resolve(new, audience=self.audience)
        with self.assertRaises(AuthorizationDenied):
            self.store.renew(refresh_token=rotated, client_id="claude-test", audience=self.audience)
        _, code = self.approve(grant_seconds=10)
        token, _ = self.exchange(code)
        refresh = self.store.issue_refresh(token, audience=self.audience)
        self.now += 10
        with self.assertRaises(AuthorizationDenied):
            self.store.renew(refresh_token=refresh, client_id="claude-test", audience=self.audience)

    def test_disconnect_revokes_codes_and_tokens_and_checks_account(self):
        grant_id, code = self.approve()
        token, _ = self.exchange(code)
        with self.assertRaises(AuthorizationDenied):
            self.store.disconnect(subject="account-b", grant_id=grant_id)
        self.store.resolve(token, audience=self.audience)
        self.store.disconnect(subject="account-a", grant_id=grant_id)
        with self.assertRaises(AuthorizationDenied):
            self.store.resolve(token, audience=self.audience)
        pending_grant, pending_code = self.approve()
        self.store.disconnect(subject="account-a", grant_id=pending_grant)
        with self.assertRaises(AuthorizationDenied):
            self.exchange(pending_code)

    def test_accounts_never_use_each_others_upstream_client(self):
        _, code_a = self.approve()
        token_a, _ = self.exchange(code_a)
        account_b = Mock(scope="authenticated_accugps_account")
        account_b.list_devices.return_value = [{"device_id": "other-account-car"}]
        account_b.query.return_value = {"data": "account-b"}
        _, code_b = self.approve(subject="account-b", account_client=account_b, device_ids=["other-account-car"])
        token_b, _ = self.exchange(code_b)
        self.assertEqual(self.store.query(token_b, audience=self.audience, device_id="other-account-car", kind="location"), {"data": "account-b"})
        self.account.query.assert_not_called()
        with self.assertRaises(ValueError):
            self.store.query(token_a, audience=self.audience, device_id="other-account-car", kind="location")

    def test_shutdown_forgets_connections_and_plain_http_denied_by_default(self):
        _, code = self.approve()
        token, _ = self.exchange(code)
        self.store.shutdown()
        with self.assertRaises(AuthorizationDenied):
            self.store.resolve(token, audience=self.audience)
        with self.assertRaises(ValueError):
            AuthorizationStore("http://example.com/mcp", {})
        AuthorizationStore("http://127.0.0.1:8767/mcp", {"test": ["http://localhost:9000/callback"]}, allow_loopback=True)
