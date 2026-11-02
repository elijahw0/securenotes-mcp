# securenotes-mcp

A read-only MCP server that lets an AI assistant query security findings from [SecureNotes](https://github.com/elijahw0/securenotes-lab).

Tools: `list_findings`, `get_finding` (validated IDs), `release_readiness` (fail-closed release gate).

Run: `python server.py` (stdio). Requires the `securenotes-lab` repo checked out next to this one.
