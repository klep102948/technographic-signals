"""Apex lookups: TXT goes over TCP (large SPF answers are truncated on UDP) and MX/TXT retry once on timeout."""
from __future__ import annotations

import asyncio

import dns.exception

from technographics import dns_collector


class FakeResolver:
    def __init__(self, fail_first: int = 0):
        self.calls: list[tuple[str, str, bool]] = []
        self.fail_first = fail_first

    async def resolve(self, name, rdtype, raise_on_no_answer=False, tcp=False):
        self.calls.append((name, rdtype, tcp))
        if self.fail_first > 0:
            self.fail_first -= 1
            raise dns.exception.Timeout()

        class Answer:
            rrset = None

        return Answer()


def test_txt_is_queried_over_tcp_and_others_over_udp():
    r = FakeResolver()
    asyncio.run(dns_collector._resolve(r, "example.com", "TXT"))
    asyncio.run(dns_collector._resolve(r, "example.com", "MX"))
    assert r.calls == [("example.com", "TXT", True), ("example.com", "MX", False)]


def test_timeout_is_retried_when_asked():
    r = FakeResolver(fail_first=1)
    assert asyncio.run(dns_collector._resolve(r, "example.com", "TXT", retries=1)) == []
    assert len(r.calls) == 2


def test_no_retry_by_default():
    r = FakeResolver(fail_first=1)
    asyncio.run(dns_collector._resolve(r, "example.com", "A"))
    assert len(r.calls) == 1


def test_apex_resolver_gets_a_longer_lifetime():
    res = dns_collector._build_resolver(["1.1.1.1"], 3.0, lifetime=3.0 * dns_collector.APEX_LIFETIME_FACTOR)
    assert res.timeout == 3.0 and res.lifetime == 9.0
