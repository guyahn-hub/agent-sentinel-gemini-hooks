#!/usr/bin/env python3
r"""
Antigravity GEMINI.md Protocol Manager (Dynamic Audit & Governance Gate)

Single Source of Truth: C:\Users\ahs01\.gemini\GEMINI.md
"""
import sys
import json
import os
import re
import datetime
from pathlib import Path

GEMINI_MD_PATH = Path(r"C:\Users\ahs01\.gemini\GEMINI.md")
LOG_PATH = Path(__file__).with_name("protocol_manager.log")

def write_log(decision: str, reason: str = "", details: str = "") -> None:
    try:
        timestamp = datetime.datetime.now().isoformat()
        log_entry = (
            f"{timestamp} | "
            f"decision={decision} | "
            f"reason={reason} | "
            f"details={details}\n"
        )
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(log_entry)
    except Exception as exc:
        sys.stderr.write(f"Protocol Manager 로그 기록 실패: {exc}\n")

def respond(decision: str, reason: str = "", details: str = "") -> None:
    write_log(decision=decision, reason=reason, details=details)
    out = {"decision": decision}
    if reason:
        out["reason"] = reason
    print(json.dumps(out, ensure_ascii=False))
    sys.exit(0)

def load_audit_rules_from_gemini_md():
    """GEMINI.md 파일에서 AUDIT_CONFIG_START ~ AUDIT_CONFIG_END 블록을 동적으로 읽어옵니다."""
    if not GEMINI_MD_PATH.exists():
        write_log("error", f"GEMINI.md 파일이 존재하지 않음: {GEMINI_MD_PATH}")
        respond("continue", reason="[Protocol Manager 오류] 단일 기준 문서(GEMINI.md)를 찾을 수 없습니다.")

    try:
        content = GEMINI_MD_PATH.read_text(encoding="utf-8", errors="ignore")
    except Exception as exc:
        write_log("error", f"GEMINI.md 읽기 실패: {exc}")
        respond("continue", reason=f"[Protocol Manager 오류] GEMINI.md 읽기 실패: {exc}")

    match = re.search(r"<!--\s*AUDIT_CONFIG_START\s*(.*?)\s*AUDIT_CONFIG_END\s*-->", content, re.DOTALL)
    if not match:
        write_log("error", "GEMINI.md 내 AUDIT_CONFIG_START 구문을 찾을 수 없음")
        respond("continue", reason="[Protocol Manager 오류] GEMINI.md 내 AUDIT_CONFIG 구문을 찾을 수 없습니다.")

    config_str = match.group(1).strip()
    try:
        rules = json.loads(config_str)
        return rules
    except Exception as exc:
        write_log("error", f"AUDIT_CONFIG JSON 파싱 실패: {exc}")
        respond("continue", reason=f"[Protocol Manager 오류] GEMINI.md 감사 규칙 JSON 파싱 실패: {exc}")

def parse_transcript(transcript_path: str):
    if not transcript_path or not os.path.exists(transcript_path):
        return []
    steps = []
    with open(transcript_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                steps.append(json.loads(line))
            except Exception:
                continue
    return steps

def is_path_under(target_path: str, base_path: str) -> bool:
    try:
        norm_t = os.path.normpath(target_path).lower()
        norm_b = os.path.normpath(base_path).lower()
        if norm_b.endswith("*"):
            prefix = norm_b[:-1]
            return norm_t.startswith(prefix)
        if norm_t == norm_b:
            return True
        t_path = Path(norm_t)
        b_path = Path(norm_b)
        return b_path in t_path.parents or norm_t.startswith(norm_b + os.sep)
    except Exception:
        return False

def evaluate_audit_rules(rules, steps, workspace_paths=None):
    last_user_idx = -1
    for i, s in enumerate(steps):
        if s.get("type") == "USER_INPUT":
            last_user_idx = i

    if last_user_idx == -1:
        return True, "", ""

    current_turn_steps = steps[last_user_idx:]

    # Collect tool sets dynamically from rules loaded from GEMINI.md
    all_mod_tools = set()
    all_insp_tools = set()
    all_verif_tools = set()
    for r in rules:
        all_mod_tools.update(r.get("modification_tools", []))
        all_insp_tools.update(r.get("inspection_tools", []))
        all_verif_tools.update(r.get("verification_tools", []))

    if not all_mod_tools:
        all_mod_tools = {"replace_file_content", "multi_replace_file_content", "write_to_file"}
    if not all_insp_tools:
        all_insp_tools = {"view_file", "grep_search", "list_dir", "read_resource"}
    if not all_verif_tools:
        all_verif_tools = {"run_command"}

    inspected_files = set()
    modified_files = []
    has_modification = False
    verification_executed = False

    for s in current_turn_steps:
        tool_calls = s.get("tool_calls") or []

        for tc in tool_calls:
            tname = tc.get("name", "")
            targs = tc.get("args", {})
            if isinstance(targs, str):
                try:
                    targs = json.loads(targs)
                except Exception:
                    targs = {}

            path = targs.get("AbsolutePath") or targs.get("SearchPath") or targs.get("TargetFile") or targs.get("DirectoryPath")

            if path and tname in all_insp_tools:
                inspected_files.add(str(path).strip('"').lower())

            if tname in all_mod_tools:
                has_modification = True
                if path:
                    norm_path = str(path).strip('"').lower()
                    modified_files.append((norm_path, tname))

            if tname in all_verif_tools:
                cmd_line = str(targs.get("CommandLine", "")).lower()
                # Ignore self-checking audit invocations
                if "protocol_manager" not in cmd_line:
                    if has_modification:
                        verification_executed = True

    # Dynamically evaluate rules loaded from GEMINI.md
    for rule in rules:
        rtype = rule.get("type")
        rid = rule.get("id", "AUDIT-UNKNOWN")
        reason_template = rule.get("reason_template", "[{id} 위반] 규약 위반")
        mod_tools = set(rule.get("modification_tools", all_mod_tools))

        if rtype == "require_preceding_inspection":
            for mod_path, tname in modified_files:
                if tname in mod_tools:
                    mod_filename = os.path.basename(mod_path)
                    inspected = any(mod_path in insp or mod_filename in insp for insp in inspected_files)
                    if not inspected and len(inspected_files) == 0:
                        reason_msg = reason_template.format(filename=mod_filename)
                        return False, reason_msg, f"Rule: {rid}, File: {mod_filename}"

        elif rtype == "require_subsequent_verification":
            if has_modification and not verification_executed:
                reason_msg = reason_template.format()
                return False, reason_msg, f"Rule: {rid}, Modifications: {len(modified_files)}"

        elif rtype == "require_workspace_boundary":
            if not workspace_paths:
                reason_msg = f"[GEMINI.md {rid} 검증 불가 (UNVERIFIABLE)] workspacePaths 정보가 없거나 유효하지 않아 SCOPE 검사를 완료할 수 없습니다."
                write_log("UNVERIFIABLE", reason_msg, f"Rule: {rid}")
                return False, reason_msg, f"Rule: {rid}, Missing workspacePaths"
            else:
                allowed_patterns = rule.get("allowed_global_patterns", [])
                all_allowed_roots = list(workspace_paths) + allowed_patterns

                for mod_path, tname in modified_files:
                    if tname in mod_tools:
                        mod_filename = os.path.basename(mod_path)
                        in_bounds = any(is_path_under(mod_path, root) for root in all_allowed_roots)
                        if not in_bounds:
                            reason_msg = reason_template.format(filename=mod_filename)
                            return False, reason_msg, f"Rule: {rid}, Out-of-bounds file: {mod_path}"

    return True, "", ""

def main():
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            payload = {}
        else:
            payload = json.loads(raw)
    except Exception as exc:
        write_log("error", f"stdin read error: {exc}")
        respond("continue", reason=f"[Protocol Manager 오류] Hook payload 읽기 실패: {exc}")

    write_log("RAW_HOOK_PAYLOAD", details=raw[:1000])

    transcript_path = payload.get("transcriptPath", "")
    if not transcript_path:
        respond("allow", details="No transcriptPath in payload")

    workspace_paths = payload.get("workspacePaths", None)

    # Single Source of Truth: load audit rules dynamically from GEMINI.md
    rules = load_audit_rules_from_gemini_md()

    passed, reason, details = evaluate_audit_rules(rules, parse_transcript(transcript_path), workspace_paths=workspace_paths)
    if not passed:
        respond("continue", reason=reason, details=details)

    respond("allow", details="Audit passed via GEMINI.md rules")

if __name__ == "__main__":
    main()
