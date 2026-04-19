"""UQL Compiler — Phase 3.

Translates a UQL query string into execution targets:
  1. ClickHouse SQL WHERE clause (field, ML score, tactic filters)
  2. Qdrant search parameters (semantic_filter → similarity query)
  3. CEP sequence pattern reference (sequence_expr → pattern_id hint)

Usage::

    from app.engine.uql.compiler import UQLCompiler

    result = UQLCompiler().compile('ml_score > 0.8 and tactic = "lateral-movement"')
    print(result.clickhouse_where)   # "meta_score > 0.8 AND JSON_EXTRACT..."
    print(result.qdrant_params)      # None (no semantic filter)
    print(result.cep_pattern_id)     # None (no sequence)
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

_GRAMMAR_PATH = Path(__file__).parent / "grammar.lark"

# Lazy-loaded parser (lark is an optional dep at import time to avoid startup cost)
_parser: Any = None


def _get_parser() -> Any:
    global _parser
    if _parser is None:
        from lark import Lark
        _parser = Lark(_GRAMMAR_PATH.read_text(), parser="earley", ambiguity="resolve")
    return _parser


# ── MITRE tactic → ClickHouse JSON path mapping ──────────────────────────────
# Events store mitre_predictions as JSON array in ClickHouse column `mitre_predictions`
_TACTIC_MAP = {
    "reconnaissance": "reconnaissance",
    "resource-development": "resource-development",
    "initial-access": "initial-access",
    "execution": "execution",
    "persistence": "persistence",
    "privilege-escalation": "privilege-escalation",
    "defense-evasion": "defense-evasion",
    "credential-access": "credential-access",
    "discovery": "discovery",
    "lateral-movement": "lateral-movement",
    "collection": "collection",
    "command-and-control": "command-and-control",
    "exfiltration": "exfiltration",
    "impact": "impact",
}

# ClickHouse column name mapping for known field names
_FIELD_ALIASES: dict[str, str] = {
    "source_type": "source_type",
    "severity": "severity",
    "source_ip": "src_ip",
    "src_ip": "src_ip",
    "tenant_id": "tenant_id",
    "action": "action",
    "message": "message",
    "event_id": "event_id",
    "campaign_id": "campaign_id",
}


@dataclass
class CompileResult:
    """Output of the UQL compiler."""
    original_uql: str
    clickhouse_where: str = "1=1"
    clickhouse_params: dict[str, Any] = field(default_factory=dict)
    qdrant_params: dict[str, Any] | None = None
    cep_pattern_id: str | None = None
    sequence_entity_field: str | None = None
    sequence_stages_where: list[str] = field(default_factory=list)
    sequence_maxspan_seconds: int | None = None
    errors: list[str] = field(default_factory=list)


class _Transformer:
    """Walks the Lark parse tree and builds CompileResult."""

    def __init__(self) -> None:
        self._ch_clauses: list[str] = []
        self._ch_params: dict[str, Any] = {}
        self._param_counter = 0
        self._qdrant_params: dict[str, Any] | None = None
        self._cep_pattern_id: str | None = None
        self._sequence_data: dict[str, Any] | None = None
        self._errors: list[str] = []

    def _next_param(self, value: Any, type_hint: str = "String") -> str:
        self._param_counter += 1
        name = f"uql_p{self._param_counter}"
        self._ch_params[name] = value
        return f"{{{name}:{type_hint}}}"

    # ── Visitors ─────────────────────────────────────────────────────────────

    def visit(self, tree: Any) -> None:
        """Entry point — recursively walk from root."""
        self._visit_node(tree)

    def _visit_node(self, node: Any) -> str | None:
        """Returns a partial ClickHouse clause for this sub-tree, or None."""
        from lark import Tree, Token

        if isinstance(node, Token):
            return str(node)

        if not isinstance(node, Tree):
            return None

        rule = node.data

        if rule == "hunt_query":
            parts = [self._visit_node(child) for child in node.children]
            self._ch_clauses.append(" AND ".join(p for p in parts if p))
            return None

        if rule == "filter_expr":
            return self._visit_filter_expr(node)

        return None

    def _visit_filter_expr(self, node: Any) -> str | None:
        from lark import Tree
        if not node.children:
            return None
        child = node.children[0]
        if not isinstance(child, Tree):
            return None

        if child.data == "ml_filter":
            return self._compile_ml_filter(child)
        if child.data == "tactic_filter":
            return self._compile_tactic_filter(child)
        if child.data == "source_filter":
            return self._compile_source_filter(child)
        if child.data == "field_filter":
            return self._compile_field_filter(child)
        if child.data == "semantic_filter":
            self._compile_semantic_filter(child)
            return None  # No CH clause for semantic
        if child.data == "sequence_expr":
            self._compile_sequence(child)
            return None
        if child.data == "filter_expr":
            # Parenthesized
            inner = self._visit_filter_expr(child)
            return f"({inner})" if inner else None
        return None

    def _compile_ml_filter(self, node: Any) -> str:
        from lark import Token
        children = node.children
        comparator = str(children[1])
        number_val = self._extract_number(children[2])
        p = self._next_param(float(number_val), "Float64")
        return f"meta_score {comparator} {p}"

    def _compile_tactic_filter(self, node: Any) -> str:
        from lark import Token
        tactic_raw = str(node.children[0]).strip('"')
        tactic_lower = tactic_raw.lower()
        safe = _TACTIC_MAP.get(tactic_lower, tactic_lower)
        p = self._next_param(safe)
        return (
            f"arrayExists(x -> JSONExtractString(x, 'tactic') = {p}, "
            f"JSONExtractArrayRaw(mitre_predictions))"
        )

    def _compile_source_filter(self, node: Any) -> str:
        value = str(node.children[0]).strip('"')
        p = self._next_param(value)
        return f"source_type = {p}"

    def _compile_field_filter(self, node: Any) -> str:
        from lark import Token
        field_name = str(node.children[0])
        comparator = str(node.children[1])
        value_node = node.children[2]
        val = self._extract_raw_value(value_node)
        ch_col = _FIELD_ALIASES.get(field_name, field_name)
        
        # Infer type hint for ClickHouse parameter
        type_hint = "String"
        if isinstance(val, (int, float)):
            type_hint = "Float64"
            
        p = self._next_param(val, type_hint)
        return f"{ch_col} {comparator} {p}"

    def _compile_semantic_filter(self, node: Any) -> None:
        query_text = str(node.children[0]).strip('"')
        # children[1] is the number tree for threshold
        threshold = self._extract_number(node.children[1])
        self._qdrant_params = {"query": query_text, "threshold": float(threshold)}

    def _compile_sequence(self, node: Any) -> None:
        from lark import Tree, Token
        entity_field = None
        stages_where: list[str] = []
        maxspan_seconds: int | None = None

        for child in node.children:
            if isinstance(child, Token) and child.type == "FIELD_NAME":
                entity_field = str(child)
            elif isinstance(child, Tree) and child.data == "sequence_stages":
                for stage_child in child.children:
                    if isinstance(stage_child, Tree) and stage_child.data == "filter_expr":
                        clause = self._visit_filter_expr(stage_child)
                        if clause:
                            stages_where.append(clause)
            elif isinstance(child, Tree) and child.data == "duration":
                maxspan_seconds = self._parse_duration(child)

        self._sequence_data = {
            "entity_field": entity_field or "src_ip",
            "stages_where": stages_where,
            "maxspan_seconds": maxspan_seconds or 900,
        }

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _extract_number(self, node: Any) -> str:
        from lark import Tree, Token
        if isinstance(node, Tree):
            parts = [str(t) for t in node.children if isinstance(t, Token)]
            return ".".join(parts) if len(parts) > 1 else parts[0] if parts else "0"
        return str(node)

    def _extract_value(self, node: Any) -> str:
        # DEPRECATED: use _extract_raw_value with _next_param
        val = self._extract_raw_value(node)
        if isinstance(val, (int, float)):
            return str(val)
        return f"'{val}'"

    def _extract_raw_value(self, node: Any) -> Any:
        from lark import Tree, Token
        if isinstance(node, Tree):
            if node.data == "field_value":
                inner = node.children[0]
                if isinstance(inner, Tree) and inner.data == "number":
                    num_str = self._extract_number(inner)
                    return float(num_str) if "." in num_str else int(num_str)
                return str(inner).strip('"\'')
            num_str = self._extract_number(node)
            return float(num_str) if "." in num_str else int(num_str)
        s = str(node).strip('"\'')
        return s

    def _parse_duration(self, node: Any) -> int:
        from lark import Tree, Token
        children = node.children
        amount = int(str(children[0]))
        unit = str(children[1])
        multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
        return amount * multipliers.get(unit, 1)

    def result(self) -> tuple[str, dict[str, Any], dict | None, dict | None]:
        ch_where = " AND ".join(c for c in self._ch_clauses if c) or "1=1"
        return ch_where, self._ch_params, self._qdrant_params, self._sequence_data


class UQLCompiler:
    """Main UQL → execution targets compiler.

    Example::

        result = UQLCompiler().compile('ml_score > 0.8 and tactic = "lateral-movement"')
    """

    def compile(self, uql: str) -> CompileResult:
        """Parse and compile a UQL string.

        Args:
            uql: UQL query string.

        Returns:
            CompileResult with CH WHERE clause, Qdrant params, sequence data.
            On parse error, returns result with ``errors`` populated and ``clickhouse_where = "1=1"``.
        """
        result = CompileResult(original_uql=uql)
        try:
            parser = _get_parser()
            tree = parser.parse(uql)
        except Exception as exc:
            msg = f"UQL parse error: {exc}"
            logger.warning("uql_parse_error", uql=uql, error=str(exc))
            result.errors.append(msg)
            return result

        try:
            transformer = _Transformer()
            transformer.visit(tree)
            ch_where, ch_params, qdrant_params, sequence_data = transformer.result()
            result.clickhouse_where = ch_where or "1=1"
            result.clickhouse_params = ch_params
            result.qdrant_params = qdrant_params
            if sequence_data:
                result.sequence_entity_field = sequence_data.get("entity_field")
                result.sequence_stages_where = sequence_data.get("stages_where", [])
                result.sequence_maxspan_seconds = sequence_data.get("maxspan_seconds")
        except Exception as exc:
            msg = f"UQL compile error: {exc}"
            logger.error("uql_compile_error", uql=uql, error=str(exc))
            result.errors.append(msg)

        logger.info(
            "uql_compiled",
            uql=uql,
            ch_where=result.clickhouse_where,
            has_qdrant=result.qdrant_params is not None,
            has_sequence=result.sequence_entity_field is not None,
        )
        return result
