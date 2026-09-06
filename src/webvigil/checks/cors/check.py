"""CORS misconfiguration check (RF-20).

This check sends one extra GET with an ``Origin`` header — the most active thing Safe Mode
does (RNF-05). It is still a plain GET and still scope-guarded.
"""

from __future__ import annotations

from webvigil.checks.base import Check
from webvigil.checks.registry import register
from webvigil.core.context import ScanContext
from webvigil.core.errors import RequestFailed
from webvigil.core.findings import Category, EvidenceItem, Finding, Location, Severity

_PROBE_ORIGIN = "https://webvigil-cors-probe.example"


@register
class CorsCheck(Check):
    id = "http.cors.misconfiguration"
    name = "CORS misconfiguration"
    category = Category.CORS
    default_severity = Severity.MEDIUM
    cwe = (942,)
    references = ("https://portswigger.net/web-security/cors",)

    async def run(self, ctx: ScanContext) -> list[Finding]:
        url = ctx.entry.url
        try:
            response = await ctx.http.get(url, headers={"Origin": _PROBE_ORIGIN})
        except RequestFailed:
            return []

        acao = response.headers.get("access-control-allow-origin")
        if acao is None:
            return []
        acac = (response.headers.get("access-control-allow-credentials") or "").strip().lower()
        credentials = acac == "true"
        location = Location(url=url, header="Access-Control-Allow-Origin")
        evidence = [
            EvidenceItem.of("request", f"Origin: {_PROBE_ORIGIN}"),
            EvidenceItem.of(
                "response",
                f"Access-Control-Allow-Origin: {acao}\n"
                f"Access-Control-Allow-Credentials: {acac or '(absent)'}",
            ),
        ]

        if acao == _PROBE_ORIGIN:
            return [
                self.finding(
                    title="Access-Control-Allow-Origin reflects the request Origin",
                    description=(
                        "The server echoes any Origin it receives into "
                        "Access-Control-Allow-Origin"
                        + (
                            " together with Access-Control-Allow-Credentials: true, which lets any "
                            "site read authenticated responses."
                            if credentials
                            else ", which effectively disables the same-origin policy for reads."
                        )
                    ),
                    remediation=(
                        "Validate Origin against an explicit allow-list and echo it only on a "
                        "match; never reflect arbitrary origins."
                    ),
                    location=location,
                    severity=Severity.HIGH if credentials else Severity.MEDIUM,
                    dedup_key="reflective-origin",
                    evidence=evidence,
                )
            ]
        if acao == "*" and credentials:
            return [
                self.finding(
                    title="Access-Control-Allow-Origin '*' combined with credentials",
                    description=(
                        "The response sends 'Access-Control-Allow-Origin: *' and "
                        "'Access-Control-Allow-Credentials: true'. Browsers reject this pair, but "
                        "it signals a broken CORS implementation with a likely exploitable path."
                    ),
                    remediation=(
                        "Do not use '*' when credentials are allowed. Echo a validated, "
                        "allow-listed Origin instead."
                    ),
                    location=location,
                    severity=Severity.HIGH,
                    dedup_key="wildcard-with-credentials",
                    evidence=evidence,
                )
            ]
        if acao.strip().lower() == "null":
            return [
                self.finding(
                    title="Access-Control-Allow-Origin allows the 'null' origin",
                    description=(
                        "'Access-Control-Allow-Origin: null' can be reached from sandboxed iframes "
                        "and other opaque origins controlled by an attacker."
                    ),
                    remediation="Never return 'null'; use an explicit allow-list of real origins.",
                    location=location,
                    severity=Severity.MEDIUM,
                    dedup_key="null-origin",
                    evidence=evidence,
                )
            ]
        return []
