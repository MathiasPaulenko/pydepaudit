import json
from pathlib import Path

import httpx
import pytest
import respx

from pydepaudit.models import Vulnerability
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
def test_query_batch_does_not_follow_external_redirect() -> None:
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(
            302, headers={"Location": "https://internal.example/metadata"}
        )
    )
    external = respx.get("https://internal.example/metadata").mock(
        return_value=httpx.Response(200, json={"results": []})
    )
    with pytest.raises(httpx.HTTPStatusError):
        OSVClient().query_batch([("pkg", "1.0")])
    assert external.call_count == 0


@respx.mock
def test_query_batch_deep_json_is_reported_as_malformed() -> None:
    body = b'{"results":[],"deep":' + b"[" * 20000 + b"0" + b"]" * 20000 + b"}"
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(200, content=body)
    )
    with pytest.raises(ValueError, match="malformed OSV JSON"):
        OSVClient().query_batch([("pkg", "1.0")])


@respx.mock
def test_hydration_does_not_follow_external_redirect() -> None:
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(
            200, json={"results": [{"vulns": [{"id": "GHSA-x"}]}]}
        )
    )
    respx.get("https://api.osv.dev/v1/vulns/GHSA-x").mock(
        return_value=httpx.Response(
            302, headers={"Location": "https://internal.example/secret"}
        )
    )
    external = respx.get("https://internal.example/secret").mock(
        return_value=httpx.Response(200, json={"id": "GHSA-x"})
    )
    vulns = OSVClient().query_batch([("pkg", "1.0")])[0]
    assert len(vulns) == 1 and vulns[0].id == "GHSA-x"
    assert external.call_count == 0


@respx.mock
def test_hydration_deep_json_keeps_lite_vulnerability() -> None:
    body = b'{"id":"GHSA-x","deep":' + b"[" * 20000 + b"0" + b"]" * 20000 + b"}"
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(
            200, json={"results": [{"vulns": [{"id": "GHSA-x"}]}]}
        )
    )
    respx.get("https://api.osv.dev/v1/vulns/GHSA-x").mock(
        return_value=httpx.Response(200, content=body)
    )
    vulns = OSVClient().query_batch([("pkg", "1.0")])[0]
    assert len(vulns) == 1 and vulns[0].id == "GHSA-x"
    assert vulns[0].summary == ""


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
                                "events": [
                                    {"introduced": "0"},
                                    {"fixed": None},
                                    {"fixed": 7},
                                    {"fixed": "1.2.3"},
                                ],
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
def test_query_batch_malformed_payload() -> None:
    # a non-dict response body must not crash with AttributeError
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(200, json=[{"vulns": []}])
    )
    assert OSVClient().query_batch([("a", "1.0")]) == [[]]


@respx.mock
def test_query_batch_per_chunk_alignment() -> None:
    # a short result list mid-stream must not shift later chunks' mappings
    calls = iter(
        [
            httpx.Response(200, json={"results": [{"vulns": []}]}),  # 1 of 500
            httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "vulns": [
                                {
                                    "id": "GHSA-z",
                                    "summary": "late",
                                    "database_specific": {"severity": "LOW"},
                                }
                            ]
                        }
                    ]
                },
            ),
        ]
    )
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        side_effect=lambda request: next(calls)
    )
    packages = [("a", "1.0")] * 501
    results = OSVClient().query_batch(packages)
    assert len(results) == 501
    assert results[0] == [] and results[499] == []
    assert results[500][0].id == "GHSA-z"  # stays aligned to its package


@respx.mock
def test_query_batch_bad_json_in_hydration() -> None:
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(
            200, json={"results": [{"vulns": [{"id": "GHSA-x"}]}]}
        )
    )
    respx.get("https://api.osv.dev/v1/vulns/GHSA-x").mock(
        return_value=httpx.Response(200, content=b"<html>not json</html>")
    )
    vulns = OSVClient().query_batch([("pkg", "1.0")])[0]
    assert len(vulns) == 1
    assert vulns[0].id == "GHSA-x"
    assert vulns[0].severity == "unknown"


@respx.mock
def test_query_batch_transitive_alias_merge() -> None:
    # V3 bridges two separate groups via aliases — all three must merge
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {
                        "vulns": [
                            {"id": "GHSA-a", "summary": "v1", "aliases": ["CVE-1"]},
                            {"id": "GHSA-b", "summary": "v2", "aliases": ["CVE-2"]},
                            {
                                "id": "GHSA-c",
                                "summary": "v3",
                                "aliases": ["CVE-2", "CVE-1"],
                            },
                        ]
                    }
                ]
            },
        )
    )
    vulns = OSVClient().query_batch([("pkg", "1.0")])[0]
    assert len(vulns) == 1
    assert vulns[0].id == "GHSA-a"
    assert set(vulns[0].aliases) == {"CVE-1", "GHSA-b", "CVE-2", "GHSA-c"}


def test_merge_vulnerability_uses_valid_id_without_duplicate_alias() -> None:
    from pydepaudit.sources.osv import _merge_vuln

    merged = _merge_vuln(
        Vulnerability("", "summary", "low"),
        Vulnerability("GHSA-1", "summary", "high"),
    )
    assert merged.id == "GHSA-1"
    assert "GHSA-1" not in merged.aliases


@respx.mock
def test_query_batch_skips_vuln_records_without_id() -> None:
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {
                        "vulns": [
                            {"id": "GHSA-1", "summary": "full record"},
                            {"id": 7, "summary": "invalid numeric identifier"},
                            {"summary": "no id"},
                            "junk",
                        ]
                    }
                ]
            },
        )
    )
    vulns = OSVClient().query_batch([("pkg", "1.0")])[0]
    assert [v.id for v in vulns] == ["GHSA-1"]


@respx.mock
def test_query_batch_invalid_vuln_id_keeps_lite() -> None:
    # a control char in the id would raise httpx.InvalidURL — keep lite record
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(
            200, json={"results": [{"vulns": [{"id": "GHSA-x\x00"}]}]}
        )
    )
    vulns = OSVClient().query_batch([("pkg", "1.0")])[0]
    assert len(vulns) == 1
    assert vulns[0].severity == "unknown"


@respx.mock
def test_query_batch_ignores_mismatched_hydration_id() -> None:
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(
            200, json={"results": [{"vulns": [{"id": "GHSA-original"}]}]}
        )
    )
    respx.get("https://api.osv.dev/v1/vulns/GHSA-original").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "GHSA-different",
                "summary": "wrong record",
                "database_specific": {"severity": "CRITICAL"},
            },
        )
    )
    vuln = OSVClient().query_batch([("pkg", "1.0")])[0][0]
    assert vuln.id == "GHSA-original"
    assert vuln.summary == ""
    assert vuln.severity == "unknown"


@respx.mock
def test_severity_non_dict_database_specific() -> None:
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {
                        "vulns": [
                            {
                                "id": "PYSEC-9",
                                "summary": "x",
                                "database_specific": "weird-string",
                                "severity": [
                                    {
                                        "type": "CVSS_V3",
                                        "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N"
                                        "/S:U/C:H/I:H/A:H",
                                    }
                                ],
                            }
                        ]
                    }
                ]
            },
        )
    )
    vuln = OSVClient().query_batch([("a", "1.0")])[0][0]
    assert vuln.severity == "critical"  # falls back to CVSS vector


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
