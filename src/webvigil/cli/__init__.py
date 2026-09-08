"""
Command-line interface for WebVigil.

A thin client over :class:`~webvigil.core.orchestrator.Orchestrator`: it parses
flags into a :class:`~webvigil.core.config.ScanConfig`, runs the scan, renders
the report, and maps the outcome to a process exit code.
"""
