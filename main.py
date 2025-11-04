from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Dict, Optional, Any
import re
import json

app = FastAPI(
    title="ABAP Rule — Replace Queries on T881/T881T/T882G with cl_fins_acdoc_util Methods",
    version="1.0"
)

# --- Rule description ---
RULE_DESC = (
    "Replaces direct database queries on tables T881, T881T, and T882G "
    "with calls to appropriate methods in class CL_FINS_ACDOC_UTIL. "
    "Use CL_FINS_ACDOC_UTIL=>GET_T881_EMU, GET_T881T_EMU, or GET_T882G_EMU respectively."
)

# --- Models ---
class Finding(BaseModel):
    pgm_name: Optional[str] = None
    inc_name: Optional[str] = None
    type: Optional[str] = None
    name: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    issue_type: Optional[str] = None
    severity: Optional[str] = None
    line: Optional[int] = None
    message: Optional[str] = None
    suggestion: Optional[str] = None
    snippet: Optional[str] = None
    meta: Optional[Dict[str, Any]] = None


class Unit(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = ""
    start_line: Optional[int] = 0
    end_line: Optional[int] = 0
    code: Optional[str] = ""
    modernize_findings: Optional[List[Finding]] = None


# --- Regex to detect SELECT queries on T881, T881T, or T882G ---
TABLE_QUERY_RE = re.compile(
    r"""
    ^\s*SELECT\s+.*?\bFROM\b\s+(?P<table>T881T?|T882G)\b
    """,
    re.IGNORECASE | re.VERBOSE | re.MULTILINE | re.DOTALL
)

# --- Utility functions ---
def line_of_offset(text: str, off: int) -> int:
    return text.count("\n", 0, off) + 1


def snippet_at(text: str, start: int, end: int) -> str:
    s = max(0, start - 60)
    e = min(len(text), end + 60)
    return text[s:e].replace("\n", "\\n")


# --- Suggestion builder ---
def build_suggestion(table: str) -> str:
    table_upper = table.upper()
    if table_upper == "T881":
        method = "CL_FINS_ACDOC_UTIL=>GET_T881_EMU"
    elif table_upper == "T881T":
        method = "CL_FINS_ACDOC_UTIL=>GET_T881T_EMU"
    else:
        method = "CL_FINS_ACDOC_UTIL=>GET_T882G_EMU"
    return (
        f"Replace direct query on table {table_upper} with a call to {method}. "
        f"This ensures compatibility with the new Universal Journal architecture."
    )


# --- Core scan logic ---
def scan_unit(unit: Unit) -> Dict[str, Any]:
    src = unit.code or ""
    findings: List[Dict[str, Any]] = []

    for m in TABLE_QUERY_RE.finditer(src):
        table = m.group("table")
        stmt_text = m.group(0)
        suggestion = build_suggestion(table)

        finding = {
            "pgm_name": unit.pgm_name,
            "inc_name": unit.inc_name,
            "type": unit.type,
            "name": unit.name,
            "start_line": unit.start_line,
            "end_line": unit.end_line,
            "issue_type": "Replace_T881_T881T_T882G_Query",
            "severity": "warning",
            "line": line_of_offset(src, m.start()),
            "message": f"Direct query on table {table.upper()} found. Replace with corresponding CL_FINS_ACDOC_UTIL method.",
            "suggestion": suggestion,
            "snippet": snippet_at(src, m.start(), m.end()),
            "meta": {
                "rule": 628,
                "original_statement": stmt_text.strip(),
                "replacement_method": suggestion,
                "note": RULE_DESC,
            },
        }
        findings.append(finding)

    obj = unit.model_dump()
    obj["modernize_findings"] = findings
    return obj


# --- Endpoint ---
@app.post("/remediate-array")
async def scan_table_replacement(units: List[Unit]):
    results = []
    for u in units:
        res = scan_unit(u)
        if res["modernize_findings"]:
            results.append(res)
    return results


@app.get("/health")
async def health():
    return {"ok": True, "rule": "Replace_T881_T881T_T882G"}
