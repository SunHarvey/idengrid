import time

import pytest

from cloudbrowser.security import NetworkPolicy, SessionTicketSigner


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1",
        "http://localhost:8080",
        "http://169.254.169.254/latest/meta-data",
        "http://10.0.0.1",
        "http://172.16.0.1",
        "http://192.168.1.1",
        "file:///etc/passwd",
    ],
)
def test_network_policy_blocks_internal_targets(url):
    assert not NetworkPolicy().is_url_allowed(url)


@pytest.mark.parametrize(
    "url", ["https://example.com", "http://api.ipify.org", "https://[2606:4700::1111]"]
)
def test_network_policy_allows_public_http_urls(url):
    assert NetworkPolicy().is_url_allowed(url)


def test_connection_ticket_is_bound_to_user_and_session_and_expires():
    signer = SessionTicketSigner("test-secret", ttl_seconds=1)
    ticket = signer.issue(user_id=7, session_id="session-a")

    assert signer.verify(ticket, user_id=7, session_id="session-a")
    assert not signer.verify(ticket, user_id=8, session_id="session-a")
    assert not signer.verify(ticket, user_id=7, session_id="session-b")
    time.sleep(1.1)
    assert not signer.verify(ticket, user_id=7, session_id="session-a")
