# securenotes-mcp

A read-only MCP server that lets an AI assistant query security findings from [SecureNotes](https://github.com/elijahw0/securenotes-lab).

Tools: `list_findings`, `get_finding` (validated IDs), `release_readiness` (fail-closed release gate).

Run: `python server.py` (stdio). Requires the `securenotes-lab` repo checked out next to this one.

## Threat Model

Assets: the integrity of the release-readiness verdict and what the server reports to a human. The three tools are read-only, but `release_readiness` advises whether SecureNotes should ship, so a wrong verdict could lead someone to release vulnerable code.

Entry points: `findings.json` is the only data the tools read (in production it'd be auto-populated by scanners, so attacker-influenceable), and the `finding_id` passed to `get_finding`.

Threats:
- Indirect prompt injection: a poisoned finding can carry text telling the model to misreport readiness. It rides in the tool output into the model's context, no direct interaction needed.
- Path traversal: if the list-findings tool took the file path as input, the model could be steered into reading any file.
- Malformed `finding_id`: unvalidated input could carry injection or cause errors.
- Info leakage: internal error details reaching the model.

Mitigations:
- `release_readiness` computes the verdict in Python from status and severity only, never the text and never by asking the model, so injection can't change the verdict, only the model's narration of it (hence human review).
- Read-only tools: nothing can write back or touch the app, so a hijacked model is limited to a misleading text reply.
- The findings path is server/env controlled, not a tool argument, so no path traversal.
- `finding_id` is validated with `fullmatch` on `SN-\d{3}`.
- The gate returns only IDs (less injectable surface), and errors return a generic message while details go to stderr.

Residual risk: the verdict is immune to injection, but a model summarizing findings could still be swayed by poisoned text, so a human approves releases. Auto-populating findings.json is future work and would widen the injection surface.