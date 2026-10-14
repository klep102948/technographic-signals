"""Collect DNS records for a domain using dnspython's async resolver.

Resolves apex A/MX/TXT/NS, then probes ``<sub>.<domain>`` CNAMEs for the union
of all vendor signatures' ``subdomains_to_probe``. All lookups are best-effort:
NXDOMAIN, timeouts, and empty answers are swallowed so a partial result is
always returned.
"""

from __future__ import annotations

import asyncio
from typing import Iterable

import dns.asyncresolver
import dns.exception
import dns.resolver

from technographics.dns_matcher import DNSRecords

DEFAULT_RESOLVERS = ["1.1.1.1", "8.8.8.8"]
DEFAULT_TIMEOUT = 3.0
# Apex records carry the strongest signals (MX, SPF/verification TXT), so they get a longer total budget across
# resolvers and one retry on timeout. TXT goes straight over TCP: SPF + verification tokens routinely exceed the
# 512-byte UDP answer, and the truncated-UDP -> TCP fallback did not fit a 3 s lifetime under load (only ~540 of 800
# real B2B domains returned TXT at 32-way concurrency; with TCP + lifetime nearly all do).
APEX_LIFETIME_FACTOR = 3.0


def _build_resolver(resolvers: list[str], timeout: float, lifetime: float | None = None) -> dns.asyncresolver.Resolver:
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = resolvers
    resolver.timeout = timeout
    resolver.lifetime = lifetime if lifetime is not None else timeout
    return resolver


async def _resolve(resolver, name: str, rdtype: str, retries: int = 0) -> list[str]:
    for attempt in range(retries + 1):
        try:
            answer = await resolver.resolve(name, rdtype, raise_on_no_answer=False, tcp=(rdtype == "TXT"))
            break
        except dns.exception.Timeout:
            if attempt < retries:
                continue
            return []
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.DNSException):
            return []
        except Exception:
            return []
    if answer.rrset is None:
        return []
    out: list[str] = []
    for record in answer:
        if rdtype == "MX":
            out.append(str(record.exchange).rstrip("."))
        elif rdtype == "TXT":
            # TXT strings come as quoted byte chunks; join them.
            out.append(b"".join(record.strings).decode("utf-8", "replace"))
        else:
            out.append(str(record).rstrip("."))
    return out


async def _resolve_cname(resolver, host: str) -> tuple[str, str] | None:
    try:
        answer = await resolver.resolve(host, "CNAME", raise_on_no_answer=False)
    except Exception:
        return None
    if answer.rrset is None:
        return None
    for record in answer:
        return host, str(record.target).rstrip(".")
    return None


async def collect_dns_async(
    domain: str,
    subdomains: Iterable[str] = (),
    resolvers: list[str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> DNSRecords:
    domain = domain.strip().strip(".").lower()
    resolver = _build_resolver(resolvers or DEFAULT_RESOLVERS, timeout)
    apex = _build_resolver(resolvers or DEFAULT_RESOLVERS, timeout, lifetime=timeout * APEX_LIFETIME_FACTOR)
    records = DNSRecords(domain=domain)

    try:
        a, mx, txt, ns, soa = await asyncio.gather(
            _resolve(apex, domain, "A"),
            _resolve(apex, domain, "MX", retries=1),
            _resolve(apex, domain, "TXT", retries=1),
            _resolve(apex, domain, "NS"),
            _resolve(apex, domain, "SOA"),
        )
        records.a, records.mx, records.txt, records.ns, records.soa = a, mx, txt, ns, soa

        subs = sorted(set(subdomains))
        if subs:
            results = await asyncio.gather(
                *[_resolve_cname(resolver, f"{sub}.{domain}") for sub in subs]
            )
            records.cname = {host: target for r in results if r for host, target in [r]}
    except Exception as exc:  # pragma: no cover - defensive
        records.error = f"{type(exc).__name__}: {exc}"

    return records


def collect_dns(
    domain: str,
    subdomains: Iterable[str] = (),
    resolvers: list[str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> DNSRecords:
    """Synchronous convenience wrapper around :func:`collect_dns_async`."""
    return asyncio.run(collect_dns_async(domain, subdomains, resolvers, timeout))
