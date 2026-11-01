"""Offline SSH authentication log analysis for a defensive security lab."""

from .detector import Config, analyze
from .parser import Event, ParseResult, parse_lines

__all__ = ["Config", "Event", "ParseResult", "analyze", "parse_lines"]
__version__ = "1.0.0"
