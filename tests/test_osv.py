import json
from pathlib import Path

import httpx
import respx

from pydepaudit.sources.osv import OSVClient


@respx.mock
def test_query_batch() -> None:
    route = respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {
                        "vulns": [
                            {
                                "id": "GHSA-xxxx-yyyy-zzzz",
                                "summary": "Bad thing",
                                "aliases": ["CVE-2024-1234"],
                                "database_specific": {"severity": "HIGH"},
                            }
                        ]
                    },
                    {"vulns": []},
                ]
            },
        )
    )

    results = OSVClient().query_batch([("a", "1.0"), ("b", "2.0")])

    body = json.loads(route.calls.last.request.content)
    assert body["queries"] == [
        {"package": {"name": "a", "ecosystem": "PyPI"}, "version": "1.0"},
        {"package": {"name": "b", "ecosystem": "PyPI"}, "version": "2.0"},
    ]
    assert len(results[0]) == 1
    vuln = results[0][0]
    assert vuln.id == "GHSA-xxxx-yyyy-zzzz"
    assert vuln.severity == "high"
    assert vuln.aliases == ("CVE-2024-1234",)
    assert "GHSA-xxxx-yyyy-zzzz" in vuln.url
    assert results[1] == []


@respx.mock
def test_query_batch_cvss_fallback() -> None:
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {
                        "vulns": [
                            {
                                "id": "PYSEC-2024-1",
                                "summary": "No GHSA severity",
                                "severity": [
                                    {
                                        "type": "CVSS_V3",
                                        "score": (
                                            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/"
                                            "S:U/C:H/I:H/A:H"
                                        ),
                                    }
                                ],
                            }
                        ]
                    }
                ]
            },
        )
    )
    results = OSVClient().query_batch([("a", "1.0")])
    assert results[0][0].severity == "high"


@respx.mock
def test_query_batch_empty() -> None:
    assert OSVClient().query_batch([]) == []


@respx.mock
def test_query_batch_hydrates_lite_records() -> None:
    # real querybatch responses only carry id+modified; details come from /vulns/{id}
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(
            200,
            json={"results": [{"vulns": [{"id": "GHSA-x", "modified": "2025-01-01"}]}]},
        )
    )
    respx.get("https://api.osv.dev/v1/vulns/GHSA-x").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "GHSA-x",
                "summary": "real bug",
                "aliases": ["CVE-2024-1"],
                "database_specific": {"severity": "HIGH"},
                "affected": [
                    {
                        "package": {"name": "pkg", "ecosystem": "PyPI"},
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [{"introduced": "0"}, {"fixed": "1.2.3"}],
                            }
                        ],
                    }
                ],
            },
        )
    )
    vulns = OSVClient().query_batch([("pkg", "1.0")])[0]
    assert vulns[0].severity == "high"
    assert vulns[0].summary == "real bug"
    assert vulns[0].aliases == ("CVE-2024-1",)
    assert vulns[0].fixed == "1.2.3"


@respx.mock
def test_query_batch_dedupes_by_alias() -> None:
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {"vulns": [{"id": "GHSA-a"}, {"id": "PYSEC-b"}, {"id": "GHSA-c"}]}
                ]
            },
        )
    )
    respx.get("https://api.osv.dev/v1/vulns/GHSA-a").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "GHSA-a",
                "summary": "same bug",
                "aliases": ["CVE-2024-1"],
                "database_specific": {"severity": "MODERATE"},
            },
        )
    )
    respx.get("https://api.osv.dev/v1/vulns/PYSEC-b").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "PYSEC-b",
                "summary": "same bug via PYSEC",
                "aliases": ["CVE-2024-1", "GHSA-a"],
                "database_specific": {"severity": "HIGH"},
            },
        )
    )
    respx.get("https://api.osv.dev/v1/vulns/GHSA-c").mock(
        return_value=httpx.Response(
            200, json={"id": "GHSA-c", "summary": "other bug", "aliases": []}
        )
    )
    vulns = OSVClient().query_batch([("pkg", "1.0")])[0]
    assert len(vulns) == 2
    dup = vulns[0]
    assert dup.id == "GHSA-a"
    assert dup.severity == "high"  # worst severity wins
    assert "PYSEC-b" in dup.aliases and "CVE-2024-1" in dup.aliases
    assert vulns[1].id == "GHSA-c"


@respx.mock
def test_query_batch_cvss_v4_vector() -> None:
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {
                        "vulns": [
                            {
                                "id": "CVE-4",
                                "summary": "",
                                "severity": [
                                    {
                                        "type": "CVSS_V4",
                                        "score": "CVSS:4.0/AV:N/AC:L/AT:N"
                                        "/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H"
                                        "/SI:H/SA:H",
                                    }
                                ],
                            }
                        ]
                    }
                ]
            },
        )
    )
    vulns = OSVClient().query_batch([("pkg", "1.0")])[0]
    assert vulns[0].severity == "critical"


@respx.mock
def test_query_batch_hydration_uses_cache(tmp_path: Path) -> None:
    from pydepaudit.cache import FileCache

    cache = FileCache(tmp_path / "cache")
    lite = {"vulns": [{"id": "GHSA-c", "modified": "2025-01-01"}]}
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(200, json={"results": [lite]})
    )
    detail = respx.get("https://api.osv.dev/v1/vulns/GHSA-c").mock(
        return_value=httpx.Response(
            200, json={"id": "GHSA-c", "summary": "cached", "aliases": []}
        )
    )
    client = OSVClient(cache=cache)
    assert client.query_batch([("p", "1.0")])[0][0].summary == "cached"
    assert client.query_batch([("p", "1.0")])[0][0].summary == "cached"
    assert detail.call_count == 1  # second batch hit the detail cache


@respx.mock
def test_query_batch_lite_fetch_failure_keeps_record() -> None:
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(
            200, json={"results": [{"vulns": [{"id": "GHSA-404"}]}]}
        )
    )
    respx.get("https://api.osv.dev/v1/vulns/GHSA-404").mock(
        return_value=httpx.Response(404)
    )
    vulns = OSVClient().query_batch([("pkg", "1.0")])[0]
    assert len(vulns) == 1
    assert vulns[0].id == "GHSA-404"
    assert vulns[0].severity == "unknown"


@respx.mock
def test_query_batch_pads_short_results() -> None:
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(200, json={"results": [{"vulns": []}]})
    )
    results = OSVClient().query_batch([("a", "1.0"), ("b", "2.0")])
    assert results == [[], []]


@respx.mock
def test_query_batch_chunks_large_inputs() -> None:
    route = respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(200, json={"results": []})
    )
    packages = [("a", "1.0")] * 501  # chunk size is 500
    results = OSVClient().query_batch(packages)
    assert route.call_count == 2
    assert results == [[]] * 501


@respx.mock
def test_vulnerability_malformed_fields() -> None:
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {
                        "vulns": [
                            {
                                "id": "PYSEC-1",
                                "summary": None,
                                "aliases": "CVE-2024-1",  # string, not list
                                "severity": [],
                            }
                        ]
                    }
                ]
            },
        )
    )
    vuln = OSVClient().query_batch([("a", "1.0")])[0][0]
    assert vuln.aliases == ()
    assert vuln.summary == ""
    assert vuln.severity == "unknown"
