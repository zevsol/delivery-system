"""Harness for Slice 2C behavior evidence using the real local MCP tools."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import sys
import tempfile
from typing import Any

from mcp import Client

from delivery_system.runtime import RuntimeContext, SQLitePreviewStore, RuntimePlanner
from mcp_server.server import create_server


ROOT = Path(__file__).parents[2]
EVIDENCE_ROOT = ROOT / ".dev" / "evals" / "slice2c" / "valid-context-cases"


def sourced(value: Any, source: str = "user_asserted") -> dict[str, Any]:
    return {"value": value, "declared_source": source}


def work_item(client_ref: str, *, title: str, problem: str, outcome: str,
              scope: list[str], non_goals: list[str], acceptance: list[str],
              verification: list[str], source: str = "user_asserted",
              role: str = "product_item") -> dict[str, Any]:
    return {
        "client_ref": client_ref,
        "role": sourced(role, source),
        "title": sourced(title, source),
        "context_problem": sourced(problem, source),
        "outcome": sourced(outcome, source),
        "scope": sourced(scope, source),
        "non_goals": sourced(non_goals, source),
        "acceptance_criteria": sourced(acceptance, source),
        "verification": sourced(verification, source),
        "required_capabilities": sourced(["issues"], source),
        "write_metadata": sourced({}, "model_proposed"),
    }


def scenario_plan(name: str) -> dict[str, Any]:
    if name == "complete-conceptual":
        return {"work_items": [work_item(
            "inventory-batches",
            title="Record inventory batches",
            problem="Inventory records cannot identify the batch associated with stock.",
            outcome="Users can record and retrieve a batch identifier for each inventory receipt.",
            scope=["inventory receipt form", "inventory lookup"],
            non_goals=["billing", "supplier reconciliation"],
            acceptance=[
                "A receipt can be saved with a non-empty batch identifier.",
                "A lookup displays the batch identifier for the selected receipt.",
            ],
            verification=["Unit tests cover save and lookup behavior with a representative receipt."],
        )], "planned_relationships": [], "operation_intents": []}
    if name == "missing-facts":
        return {"work_items": [work_item(
            "notification-policy",
            title="Choose notification policy",
            problem="The required recipient policy has not been confirmed by the product owner.",
            outcome="The system uses the correct notification recipient policy.",
            scope=["notification routing"],
            non_goals=["message template redesign"],
            acceptance=[],
            verification=[],
            source="model_assumption",
        )], "planned_relationships": [], "operation_intents": []}
    if name == "decomposition-and-relations":
        return {"work_items": [
            work_item(
                "dashboard-and-migration",
                title="Build dashboard and migrate historical records",
                problem="Operators need a dashboard while historical records remain in a legacy format.",
                outcome="Operators can use the dashboard and all historical records are migrated.",
                scope=["dashboard", "data migration", "legacy import", "reporting"],
                non_goals=["new analytics definitions"],
                acceptance=["The dashboard is available."],
                verification=["Run a smoke test."],
            ),
            work_item(
                "dashboard-widgets",
                title="Add dashboard widgets",
                problem="The dashboard needs several widgets.",
                outcome="The dashboard shows the required widgets.",
                scope=["dashboard", "reporting"],
                non_goals=["data migration"],
                acceptance=["Widgets render."],
                verification=["Run a smoke test."],
            ),
        ], "planned_relationships": [{
            "kind": "planned_parent",
            "from_client_ref": "dashboard-and-migration",
            "to_client_ref": "dashboard-widgets",
            "rationale": sourced("The larger item includes the widget work.", "model_assumption"),
        }], "operation_intents": []}
    raise ValueError(f"unknown scenario: {name}")


def _json_dump(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


async def _generate(name: str, case_dir: Path) -> None:
    workspaces = case_dir / "workspaces"
    workspaces.mkdir(parents=True, exist_ok=True)
    workspace = Path(tempfile.mkdtemp(prefix=f"{name}-", dir=workspaces))
    context = RuntimeContext.from_workspace_root(workspace)
    store = SQLitePreviewStore(
        context,
        ignore_checker=lambda _: True,
        tracked_checker=lambda _: False,
    )
    server = create_server(context, store)
    plan = scenario_plan(name)
    async with Client(server, raise_exceptions=True) as client:
        preview = await client.call_tool("delivery_plan_preview", {"payload": {"plan": plan}})
        preview_value = preview.structured_content
        audit_context = await client.call_tool("delivery_get_audit_context", {"payload": {
            "preview_id": preview_value["preview_id"],
            "revision": preview_value["revision"],
        }})
        context_value = audit_context.structured_content
    if context_value["context_status"] != "audit_ready":
        raise RuntimeError("audit_context_not_ready")
    if not context_value["rule_registry_version"] or not context_value["rule_registry_digest"]:
        raise RuntimeError("audit_rule_registry_missing")
    if not context_value["audit_context_digest"] or not context_value["sealed_preview"]:
        raise RuntimeError("audit_context_incomplete")
    _json_dump(case_dir / "audit-context.json", context_value)
    _json_dump(case_dir / "preview-output.json", preview_value)
    _json_dump(case_dir / "scenario-plan.json", plan)
    (case_dir / "workspace-path.txt").write_text(str(workspace) + "\n", encoding="utf-8")
    (case_dir / "request.txt").write_text(
        f"Please audit Preview {context_value['preview_id']} Revision {context_value['revision']}.\n",
        encoding="utf-8",
    )


async def _record(case_dir: Path, payload_path: Path) -> None:
    context_value = json.loads((case_dir / "audit-context.json").read_text(encoding="utf-8"))
    workspace = Path((case_dir / "workspace-path.txt").read_text(encoding="utf-8").strip())
    context = RuntimeContext.from_workspace_root(workspace)
    store = SQLitePreviewStore(
        context,
        ignore_checker=lambda _: True,
        tracked_checker=lambda _: False,
    )
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    request = {
        "preview_id": context_value["preview_id"],
        "revision": context_value["revision"],
        "expected_audit_context_digest": context_value["audit_context_digest"],
        "semantic_evaluations": payload.get("semantic_evaluations", []),
        "finding_drafts": payload.get("finding_drafts", []),
    }
    _json_dump(case_dir / "runtime-submission.json", request)
    server = create_server(context, store)
    try:
        async with Client(server, raise_exceptions=True) as client:
            result = await client.call_tool("delivery_record_audit", {"payload": request})
            output = result.structured_content
            if output is None:
                output = {"structured_content": None, "mcp_result": result.model_dump(mode="json")}
        _json_dump(case_dir / "runtime-output.json", output)
        (case_dir / "runtime-status.txt").write_text("accepted\n", encoding="utf-8")
    except Exception as exc:
        (case_dir / "runtime-status.txt").write_text("rejected\n", encoding="utf-8")
        _json_dump(case_dir / "runtime-error.json", {"error_type": type(exc).__name__, "message": str(exc)})
        raise


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("generate", "record"))
    parser.add_argument("scenario", choices=("complete-conceptual", "missing-facts", "decomposition-and-relations"))
    parser.add_argument("payload", nargs="?")
    args = parser.parse_args()
    case_dir = EVIDENCE_ROOT / args.scenario
    case_dir.mkdir(parents=True, exist_ok=True)
    if args.mode == "generate":
        asyncio.run(_generate(args.scenario, case_dir))
    else:
        if not args.payload:
            parser.error("record requires an agent payload path")
        asyncio.run(_record(case_dir, Path(args.payload)))


if __name__ == "__main__":
    main()
