import json
import logging
import sys
from pathlib import Path

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

# Logs to stderr
logging.basicConfig(level=logging.INFO, stream=sys.stderr, force=True)
logger = logging.getLogger(__name__)

server = MCPServer("SecureNotesMCP", version="1.0.0")

path = Path(__file__).parent.parent / "securenotes-lab" / "findings.json"


@server.tool("list_findings")
def list_findings() -> list[dict]:
    """
    This function loads vulnerability findings from securenotes as JSON of a list of dictionaries.
    Use when you want to scope out the vulnerabilities it may have.
    Each finding contains the following keys:
    id - unique identifier for each finding
    title - brief summary of the finding
    owasp_category - OWASP category the finding belongs to
    severity - severity level of the finding
    endpoint - API endpoint affected by the finding
    status - current status of the finding
    root_cause - underlying cause of the finding
    fix - recommended fix for the finding
    test - test cases to verify the fix
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            findings = json.load(f)
        return findings

    except FileNotFoundError as e:
        logger.error("Findings file not found: %s", e)
        raise ToolError("Error loading findings: File not found") from None
    except json.JSONDecodeError as e:
        logger.error("Findings file is not valid JSON: %s", e)
        raise ToolError("Error loading findings: Invalid JSON") from None


if __name__ == "__main__":
    server.run()