"""SSRF protection tests for url_extractor.resolve_url.

No external network: private/loopback/link-local hosts resolve locally and must be
blocked WITHOUT any fetch.
"""
import asyncio

import app.parser.url_extractor as ue


def test_is_public_host_blocks_internal():
    for host in ("127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1",
                 "169.254.169.254", "localhost", "0.0.0.0", ""):
        assert ue._is_public_host(host) is False, host


def test_resolve_url_refuses_metadata_endpoint():
    # AWS metadata IP — must be returned unfetched, not followed.
    target = "http://169.254.169.254/latest/meta-data/"
    assert asyncio.run(ue.resolve_url(target)) == target


def test_resolve_url_refuses_loopback():
    target = "http://127.0.0.1:8000/api/settings"
    assert asyncio.run(ue.resolve_url(target)) == target
