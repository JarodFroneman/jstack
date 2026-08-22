from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from typing import Any, Iterator, Tuple

try:
    import jsonschema
except ImportError:  # The production runtime intentionally has no schema dependency.
    jsonschema = None  # type: ignore[assignment]

from mcp.jstack import prompt_compiler


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "mcp" / "jstack" / "schemas"
SCHEMA_NAMES = (
    "prompt-intent.v1.schema.json",
    "prompt-compilation.v1.schema.json",
    "prompt-compilation.v2.schema.json",
)


def load_schema(name: str) -> dict[str, Any]:
    return json.loads((SCHEMA_ROOT / name).read_text(encoding="utf-8"))


def walk_schema(
    value: Any, path: Tuple[str, ...] = ()
) -> Iterator[Tuple[Tuple[str, ...], dict[str, Any]]]:
    if isinstance(value, dict):
        yield path, value
        for key, child in value.items():
            yield from walk_schema(child, path + (key,))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk_schema(child, path + (str(index),))


def sample_intent() -> dict[str, Any]:
    return prompt_compiler.compile_intent(
        raw_request="Implement strict parser validation and run focused tests. Do not deploy.",
        workflow_mode="j-stack-dev",
    )


def sample_compilation() -> dict[str, Any]:
    intent = sample_intent()
    return prompt_compiler.compile_grounded(
        intent=intent,
        workflow_mode="j-stack-dev",
        risk_tier="medium",
        grounding={
            "sources": [
                {
                    "field": "parser_location",
                    "value": "The parser is implemented in parser.py.",
                    "source_kind": "repository",
                    "source_reference": "parser.py:1",
                }
            ],
            "requirements": [
                {
                    "id": "user-goal",
                    "category": "scope",
                    "statement": intent["normalizedGoal"],
                    "material": True,
                    "status": "required",
                    "source_kind": "explicit-user",
                    "source_reference": "raw-prompt-sha256:" + intent["rawPromptDigest"],
                }
            ],
            "acceptance_criteria": ["Invalid input is rejected and valid input remains accepted."],
            "verification_requirements": ["Run focused parser tests."],
            "likely_in_scope": ["parser.py", "tests/test_parser.py"],
        },
        readiness={
            "state": "ready",
            "readyForPlanning": True,
            "briefDigest": "a" * 64,
            "questionCount": 0,
            "materialGapCount": 0,
        },
    )


class PromptSchemaStructureTests(unittest.TestCase):
    def test_schemas_are_draft_2020_12_and_close_compiler_contracts(self) -> None:
        for name in SCHEMA_NAMES:
            schema = load_schema(name)
            self.assertEqual(
                "https://json-schema.org/draft/2020-12/schema", schema["$schema"]
            )
            self.assertFalse(schema["additionalProperties"])
            for path, node in walk_schema(schema):
                if node.get("type") != "object":
                    continue
                self.assertIs(
                    node.get("additionalProperties"),
                    False,
                    "%s:%s" % (name, "/".join(path)),
                )

    def test_current_compilation_requires_exact_prompt_approval_state(self) -> None:
        schema = load_schema("prompt-compilation.v2.schema.json")
        self.assertIn("approval", schema["required"])
        self.assertEqual(3, len(schema["allOf"]))
        compilation = sample_compilation()
        self.assertEqual("jstack.prompt-compilation.v2", compilation["schemaVersion"])
        self.assertEqual("awaiting_prompt_approval", compilation["readiness"]["state"])
        self.assertFalse(compilation["readiness"]["readyForPlanning"])
        self.assertEqual("awaiting-user", compilation["approval"]["state"])
        self.assertFalse(compilation["approval"]["approved"])
        self.assertEqual(
            compilation["renderedPromptSha256"],
            compilation["approval"]["renderedPromptSha256"],
        )


@unittest.skipIf(jsonschema is None, "jsonschema is not installed in the production runtime")
class PromptSchemaValidationTests(unittest.TestCase):
    def validator(self, name: str) -> Any:
        schema = load_schema(name)
        jsonschema.Draft202012Validator.check_schema(schema)
        return jsonschema.Draft202012Validator(schema)

    def test_runtime_instances_validate(self) -> None:
        self.validator("prompt-intent.v1.schema.json").validate(sample_intent())
        self.validator("prompt-compilation.v2.schema.json").validate(
            sample_compilation()
        )

    def test_unknown_fields_are_rejected(self) -> None:
        instances = {
            "prompt-intent.v1.schema.json": sample_intent(),
            "prompt-compilation.v2.schema.json": sample_compilation(),
        }
        for name, instance in instances.items():
            candidate = copy.deepcopy(instance)
            candidate["unexpected"] = True
            with self.assertRaises(jsonschema.ValidationError, msg=name):
                self.validator(name).validate(candidate)


if __name__ == "__main__":
    unittest.main()
