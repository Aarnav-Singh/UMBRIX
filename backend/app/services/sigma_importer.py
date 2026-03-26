"""Sigma Rule Importer — ingest community/commercial Sigma YAML rules.

Parses standard Sigma rules (https://github.com/SigmaHQ/sigma)
and converts them into internal detection conditions that can be
evaluated against OCSF-normalized events in the pipeline.

Phase 30.4: Initial implementation supporting:
  - Sigma rule YAML parsing with full metadata extraction
  - Condition-to-filter translation for pipeline evaluation
  - Batch import from directories
  - Rule lifecycle management (versioning, enable/disable)
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import yaml
import structlog

logger = structlog.get_logger(__name__)


class SigmaRule:
    """Parsed representation of a single Sigma rule."""

    def __init__(
        self,
        id: str,
        title: str,
        description: str,
        status: str,
        level: str,
        logsource: dict[str, str],
        detection: dict[str, Any],
        tags: list[str],
        author: str = "",
        date: str = "",
        references: list[str] | None = None,
        falsepositives: list[str] | None = None,
        raw_yaml: str = "",
    ) -> None:
        self.id = id
        self.title = title
        self.description = description
        self.status = status
        self.level = level
        self.logsource = logsource
        self.detection = detection
        self.tags = tags
        self.author = author
        self.date = date
        self.references = references or []
        self.falsepositives = falsepositives or []
        self.raw_yaml = raw_yaml
        self.enabled = True
        self.imported_at = datetime.utcnow().isoformat()
        self.match_count = 0
        self.last_matched_at = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "status": self.status,
            "level": self.level,
            "logsource": self.logsource,
            "detection": self.detection,
            "tags": self.tags,
            "author": self.author,
            "date": self.date,
            "references": self.references,
            "falsepositives": self.falsepositives,
            "enabled": self.enabled,
            "imported_at": self.imported_at,
            "match_count": self.match_count,
            "last_matched_at": self.last_matched_at,
        }


class SigmaConditionCompiler:
    """Translates Sigma detection blocks into executable filter functions."""

    @staticmethod
    def compile_selection(selection: dict[str, Any]) -> dict[str, Any]:
        """Convert a Sigma selection block into a flat filter dict.

        Sigma selections use field|modifier syntax. We translate common
        modifiers into a normalized filter representation. Supports 'not field'.
        """
        filters: dict[str, Any] = {}
        for key, value in selection.items():
            if str(key).startswith("not "):
                field_name = key[4:].strip()
                modifier = "not"
            else:
                parts = key.split("|")
                field_name = parts[0]
                modifier = parts[1] if len(parts) > 1 else "equals"

            filters[field_name] = {
                "modifier": modifier,
                "values": value if isinstance(value, list) else [value],
            }
        return filters

    @staticmethod
    def compile_condition(detection: dict[str, Any]) -> dict[str, Any]:
        """Compile the full detection block into an evaluatable structure.

        Returns a dict with:
          - selections: named filter groups
          - condition: the logical expression combining them
        """
        condition_expr = detection.get("condition", "selection")
        selections = {}

        for key, value in detection.items():
            if key == "condition":
                continue
            if isinstance(value, dict):
                selections[key] = SigmaConditionCompiler.compile_selection(value)
            elif isinstance(value, list):
                # OR-linked list of selection dicts
                selections[key] = [
                    SigmaConditionCompiler.compile_selection(item)
                    if isinstance(item, dict)
                    else item
                    for item in value
                ]

        return {
            "selections": selections,
            "condition": condition_expr,
        }


class SigmaImporter:
    """Service for importing and managing Sigma rules."""

    def __init__(self, postgres: Any = None) -> None:
        self._rules: dict[str, SigmaRule] = {}
        self._compiled: dict[str, dict] = {}
        self._postgres = postgres

    def import_file(self, filepath: str) -> SigmaRule | None:
        """Import a single Sigma YAML rule file."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                raw = f.read()
                data = yaml.safe_load(raw)

            if not data or "detection" not in data:
                logger.warning("sigma_invalid_rule", path=filepath, reason="No detection block")
                return None

            rule = SigmaRule(
                id=data.get("id", str(uuid.uuid4())),
                title=data.get("title", Path(filepath).stem),
                description=data.get("description", ""),
                status=data.get("status", "experimental"),
                level=data.get("level", "medium"),
                logsource=data.get("logsource", {}),
                detection=data.get("detection", {}),
                tags=data.get("tags", []),
                author=data.get("author", ""),
                date=data.get("date", ""),
                references=data.get("references", []),
                falsepositives=data.get("falsepositives", []),
                raw_yaml=raw,
            )

            self._rules[rule.id] = rule
            self._compiled[rule.id] = SigmaConditionCompiler.compile_condition(rule.detection)

            logger.info(
                "sigma_rule_imported",
                rule_id=rule.id,
                title=rule.title,
                level=rule.level,
                tags=rule.tags,
            )
            return rule

        except Exception as exc:
            logger.error("sigma_import_failed", path=filepath, error=str(exc))
            return None

    def import_directory(self, dirpath: str, recursive: bool = True) -> list[SigmaRule]:
        """Batch import all .yml/.yaml Sigma rules from a directory."""
        imported: list[SigmaRule] = []
        pattern = "**/*.yml" if recursive else "*.yml"

        for yml_path in Path(dirpath).glob(pattern):
            rule = self.import_file(str(yml_path))
            if rule:
                imported.append(rule)

        # Also check .yaml extension
        yaml_pattern = "**/*.yaml" if recursive else "*.yaml"
        for yaml_path in Path(dirpath).glob(yaml_pattern):
            rule = self.import_file(str(yaml_path))
            if rule:
                imported.append(rule)

        logger.info("sigma_batch_import_complete", count=len(imported), directory=dirpath)
        return imported

    def evaluate(self, rule_id: str, event: dict[str, Any]) -> bool:
        """Evaluate a compiled Sigma rule against a single OCSF event.

        Returns True if the event matches the rule's detection logic.
        """
        compiled = self._compiled.get(rule_id)
        if not compiled:
            return False

        rule = self._rules.get(rule_id)
        if not rule or not rule.enabled:
            return False

        selections = compiled["selections"]
        condition = compiled["condition"]

        # Simple condition evaluation (handles "selection" and "selection and not filter")
        selection_results: dict[str, bool] = {}
        for sel_name, sel_filters in selections.items():
            if isinstance(sel_filters, dict):
                selection_results[sel_name] = self._match_selection(sel_filters, event)
            elif isinstance(sel_filters, list):
                # OR-linked: any match satisfies
                selection_results[sel_name] = any(
                    self._match_selection(f, event) for f in sel_filters if isinstance(f, dict)
                )

        # Parse the simple condition expression
        return self._evaluate_condition(condition, selection_results)

    def evaluate_all(self, event: dict[str, Any]) -> list[SigmaRule]:
        """Evaluate all enabled rules against an event. Returns matching rules."""
        matches: list[SigmaRule] = []
        for rule_id, rule in self._rules.items():
            if rule.enabled and self.evaluate(rule_id, event):
                rule.match_count += 1
                rule.last_matched_at = datetime.utcnow().isoformat()
                matches.append(rule)
        return matches

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    @property
    def enabled_rules(self) -> list[SigmaRule]:
        return [r for r in self._rules.values() if r.enabled]

    def disable_rule(self, rule_id: str) -> None:
        if rule_id in self._rules:
            self._rules[rule_id].enabled = False

    def enable_rule(self, rule_id: str) -> None:
        if rule_id in self._rules:
            self._rules[rule_id].enabled = True

    # ── Internal matching ──────────────────────────────

    @staticmethod
    def _match_selection(filters: dict[str, Any], event: dict[str, Any]) -> bool:
        """Check if an event matches ALL filters in a selection (AND logic)."""
        for field, criteria in filters.items():
            event_value = event.get(field)
            if event_value is None:
                return False

            modifier = criteria.get("modifier", "equals")
            values = criteria.get("values", [])

            if modifier == "equals":
                if event_value not in values:
                    return False
            elif modifier == "not":
                if event_value in values:
                    return False
            elif modifier == "contains":
                if not any(str(v).lower() in str(event_value).lower() for v in values):
                    return False
            elif modifier == "startswith":
                if not any(str(event_value).startswith(str(v)) for v in values):
                    return False
            elif modifier == "endswith":
                if not any(str(event_value).endswith(str(v)) for v in values):
                    return False
            elif modifier == "re":
                import re
                if not any(re.search(str(v), str(event_value)) for v in values):
                    return False

        return True

    @staticmethod
    def _evaluate_condition(condition: str, results: dict[str, bool]) -> bool:
        """Evaluate a simple Sigma condition expression."""
        condition = condition.strip()

        # Handle "X and not Y"
        if " and not " in condition:
            parts = condition.split(" and not ")
            pos = parts[0].strip()
            neg = parts[1].strip()
            return results.get(pos, False) and not results.get(neg, False)

        # Handle "X or Y"
        if " or " in condition:
            return any(results.get(p.strip(), False) for p in condition.split(" or "))

        # Handle "X and Y"
        if " and " in condition:
            return all(results.get(p.strip(), False) for p in condition.split(" and "))

        # Handle "not X"
        if condition.startswith("not "):
            return not results.get(condition[4:].strip(), False)

        # Simple single selection
        return results.get(condition, False)
