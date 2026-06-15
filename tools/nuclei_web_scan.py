"""
Nuclei Web Scan (alias for nuclei:full_scan)
LLMs frequently hallucinate this tool name. This alias delegates to nuclei:full_scan
to prevent failed dispatches in agentic workflows.
"""

from tools.nuclei_full_scan import NucleiFullScanTool


class NucleiWebScanTool(NucleiFullScanTool):
    """Alias - delegates entirely to NucleiFullScanTool."""

    @property
    def name(self) -> str:
        return "nuclei:web_scan"

    @property
    def description(self) -> str:
        return (
            "Web vulnerability scan using Nuclei templates (alias for nuclei:full_scan). "
            "Scans with technologies, exposed-panels, misconfiguration, vulnerabilities, CVEs, and exposures templates."
        )

    @property
    def metadata(self):
        base = super().metadata
        return {**base, "alias_of": "nuclei:full_scan"}


def get_tool():
    return NucleiWebScanTool()
