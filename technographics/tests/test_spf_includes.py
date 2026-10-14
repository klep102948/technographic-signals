"""SPF-include TXT signatures: email-sending platforms show up in the apex SPF record even when the website
carries no tag (a static fetch misses script-injected HubSpot/Marketo tags)."""
from __future__ import annotations

import pytest

from technographics.dns_matcher import DNSMatcher, DNSRecords
from technographics.loader import load_library


@pytest.fixture(scope="module")
def matcher() -> DNSMatcher:
    lib = load_library(include_master=False)
    return DNSMatcher(lib.dns_signatures, lib.vendors)


def vendors(matcher: DNSMatcher, *txt: str) -> dict:
    return {d.vendor_id: d for d in matcher.match(DNSRecords(domain="example.com", txt=list(txt)))}


@pytest.mark.parametrize(
    "spf, vendor",
    [
        ("v=spf1 include:spf.protection.outlook.com include:144358290.spf04.hubspotemail.net -all", "hubspot"),
        ("v=spf1 include:25356753.spf10.hubspotemail.net ~all", "hubspot"),
        ("v=spf1 include:7462085.spf03.hubspotemail.net include:_spf.google.com ~all", "hubspot"),
        ("v=spf1 include:_spf.salesforce.com include:_spf.google.com ~all", "salesforce"),
        ("v=spf1 ip4:1.2.3.4 include:mktomail.com -all", "marketo"),
        ("v=spf1 include:aspmx.pardot.com include:spf.protection.outlook.com -all", "pardot"),
        ("v=spf1 include:mail.zendesk.com ~all", "zendesk"),
    ],
)
def test_spf_include_detects_sender(matcher, spf, vendor):
    found = vendors(matcher, spf)
    assert vendor in found
    assert found[vendor].confidence >= 0.8


def test_hubspot_spf_marks_paid_tier(matcher):
    assert vendors(matcher, "v=spf1 include:1234.spf02.hubspotemail.net -all")["hubspot"].tier_signal == "paid"


@pytest.mark.parametrize(
    "txt",
    [
        "v=spf1 include:spf.protection.outlook.com -all",
        "hubspot-developer-verification=abc123",  # a developer account, not a sending domain
        "v=spf1 include:mail.example-hubspotemail.net.evil.com -all",
    ],
)
def test_no_false_hubspot(matcher, txt):
    assert "hubspot" not in vendors(matcher, txt)
