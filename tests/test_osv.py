import json

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
