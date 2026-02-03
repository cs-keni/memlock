# Pydantic data models for vulnerability findings: Finding, Location, Severity.

from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field


class Location(BaseModel):
    """Where in the source a finding was reported (file, line, column)."""

    path: Path
    line: int = Field(..., ge=1, description="1-based line number")
    column: int = Field(..., ge=1, description="1-based column number")
    end_line: Optional[int] = Field(None, ge=1)
    end_column: Optional[int] = Field(None, ge=1)
    snippet: Optional[str] = None

    model_config = {"arbitrary_types_allowed": True}


class Finding(BaseModel):
    """A single issue reported by a rule (e.g. buffer overflow at line 42)."""

    rule_id: str
    message: str
    location: Location
    severity: str = Field(default="warning", description="e.g. error, warning, info")

    model_config = {"arbitrary_types_allowed": True}
