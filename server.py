import json
import logging
import sys
import re
from pathlib import Path
import os

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

# Logs to stderr
logging.basicConfig(level=logging.INFO, stream=sys.stderr, force=True)
logger = logging.getLogger(__name__)

server = MCPServer("SecureNotesMCP", version="1.0.0")

env_file = os.environ.get("FINDINGS")
if env_file:
    path = Path(__file__).parent / env_file
else:
    path = Path(__file__).parent.parent / "securenotes-lab" / "findings.json"

SAFE_STATUSES = {"fixed"}
NON_BLOCKING_SEVERITIES = {"medium", "low"}

def _load_findings() -> list[dict]:
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
    return _load_findings()


@server.tool("get_finding")
def get_finding(finding_id: str) -> dict:
    """
    Args:
        finding_id (str): The unique identifier for the finding to retrieve. Format example : SN-001
        
    This function retrieves a specific vulnerability finding by its unique identifier.
    Use when you want to get detailed information about a specific finding.
    Each finding contains the following keys:
    id - unique identifier for each finding format: SN-xxx
    title - brief summary of the finding
    owasp_category - OWASP category the finding belongs to
    severity - severity level of the finding
    endpoint - API endpoint affected by the finding
    status - current status of the finding
    root_cause - underlying cause of the finding
    fix - recommended fix for the finding
    test - test cases to verify the fix
    """
    if not re.fullmatch(r"SN-\d{3}", finding_id):
        logger.warning("Finding with ID %r not found", finding_id)
        raise ToolError("Finding with ID not found, expected format: SN-xxx")

    findings = _load_findings()
    for finding in findings:
        if finding.get("id") == finding_id:
            return finding
        
    logger.info("Finding %s not found", finding_id)
    raise ToolError(f"Finding {finding_id} not found.")

@server.tool("release_readiness")
def release_readiness() -> dict:
    """
    This function checks the release readiness of the application.
    It ensures that all findings have a status of 'fixed' or a 'low' or 'medium' severity level, indicating that they are not critical vulnerabilities. 
    If the findings report yield results that are currently open and high in severity, they block the release.
    Returns a dictionary with keys 'ready' (bool) and the 'blockers' (list of findings). If 'ready' is True, 'blockers' will be empty.
    """
    findings = _load_findings()
    blockers = []
    
    for finding in findings:
        status = finding.get("status")
        severity = finding.get("severity")

        # adds to blocker if status or severity is invalid
        if not isinstance(status, str) or not isinstance(severity, str):
            logger.warning("Finding %r has a missing or invalid status/severity. Blocking release", finding.get("id"))
            blockers.append(finding.get("id"))
            continue

        # block if status or severity is not a known option
        if status.lower() not in SAFE_STATUSES and severity.lower() not in NON_BLOCKING_SEVERITIES:
            blockers.append(finding.get("id"))

    if blockers:
        logger.info("Release blocked by findings: %s", blockers)
        return {"ready": False, "blockers": blockers}

    logger.info("All findings are ready for release")
    return {"ready": True, "blockers": blockers}
        


if __name__ == "__main__":
    server.run()