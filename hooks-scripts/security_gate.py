"""
Antigravity Global Security Gate

역할:
- Antigravity PreToolUse 요청을 가장 먼저 검사합니다.
- 실제 보안 규칙은 rules.py에서 가져옵니다.
- 위험 요소가 발견되면 tool 실행을 차단합니다.
- 위험 요소가 없으면 tool 실행을 허용합니다.

구조:

    Antigravity
        ↓
    security_gate.py
        ↓
    rules.py
        ↓
    ALLOW / DENY
"""

import json
import os
import re
import sys
import datetime
from pathlib import Path

import rules


# ============================================================
# 로그 파일
# ============================================================

LOG_PATH = Path(__file__).with_name("security_gate.log")


# ============================================================
# 로그
# ============================================================

def write_log(
    tool_name: str,
    command_line: str,
    cwd_value: str,
    decision: str,
    reason: str = ""
) -> None:
    """보안 게이트 검사 결과를 기록합니다."""

    try:
        timestamp = datetime.datetime.now().isoformat()

        log_entry = (
            f"{timestamp} | "
            f"tool={tool_name} | "
            f"decision={decision} | "
            f"CommandLine={command_line} | "
            f"Cwd={cwd_value} | "
            f"reason={reason}\n"
        )

        with open(LOG_PATH, "a", encoding="utf-8") as log_file:
            log_file.write(log_entry)

    except Exception as exc:

        # 로그 실패 때문에 보안 게이트 자체가 죽지 않도록 합니다.
        sys.stderr.write(
            f"보안 게이트 로그 기록 실패: {exc}\n"
        )


# ============================================================
# 차단
# ============================================================

def deny(
    reason: str,
    tool_name: str = "",
    command_line: str = "",
    cwd_value: str = ""
) -> None:
    """도구 실행을 차단합니다."""

    write_log(
        tool_name=tool_name,
        command_line=command_line,
        cwd_value=cwd_value,
        decision="deny",
        reason=reason
    )

    print(
        json.dumps(
            {
                "decision": "deny",
                "reason": reason
            },
            ensure_ascii=False
        )
    )

    sys.exit(0)


# ============================================================
# 허용
# ============================================================

def allow(
    tool_name: str = "",
    command_line: str = "",
    cwd_value: str = ""
) -> None:
    """도구 실행을 허용합니다."""

    write_log(
        tool_name=tool_name,
        command_line=command_line,
        cwd_value=cwd_value,
        decision="allow"
    )

    print(
        json.dumps(
            {
                "decision": "allow"
            },
            ensure_ascii=False
        )
    )

    sys.exit(0)


# ============================================================
# 문자열 추출
# ============================================================

def collect_strings(value) -> list[str]:
    """
    toolCall args 안에 있는 문자열을 재귀적으로 수집합니다.

    Antigravity가 파일 경로나 명령어를 어떤 key 이름으로
    전달하더라도 일단 문자열을 확보할 수 있도록 합니다.
    """

    result = []

    if isinstance(value, str):

        result.append(value)

    elif isinstance(value, dict):

        for item in value.values():
            result.extend(collect_strings(item))

    elif isinstance(value, list):

        for item in value:
            result.extend(collect_strings(item))

    return result


# ============================================================
# 위험 명령 검사
# ============================================================

def check_dangerous_command(
    command_line: str,
    tool_name: str,
    cwd_value: str
) -> None:
    """
    rules.py의 위험 명령 패턴을 검사합니다.

    위험 명령이 발견되면 즉시 차단합니다.
    """

    if not command_line:
        return

    lowered_command = command_line.lower()

    for pattern in rules.DANGEROUS_COMMAND_PATTERNS:

        try:

            if re.search(pattern, lowered_command):

                deny(
                    reason=(
                        "rules.py의 위험 명령 규칙에 "
                        "해당하여 차단했습니다: "
                        f"{command_line}"
                    ),
                    tool_name=tool_name,
                    command_line=command_line,
                    cwd_value=cwd_value
                )

        except re.error as exc:

            # 보안 규칙 자체가 잘못되었다면
            # 안전을 위해 차단합니다.
            if rules.DENY_ON_SECURITY_CHECK_ERROR:

                deny(
                    reason=(
                        "보안 규칙을 검사하는 중 오류가 "
                        f"발생했습니다: {exc}"
                    ),
                    tool_name=tool_name,
                    command_line=command_line,
                    cwd_value=cwd_value
                )


# ============================================================
# 민감 파일 검사
# ============================================================

def is_sensitive_path(path_value: str) -> bool:
    """rules.py의 민감 파일 규칙에 해당하는지 검사합니다."""

    if not path_value:
        return False

    for pattern in rules.SENSITIVE_FILE_PATTERNS:

        try:

            if re.search(pattern, path_value, re.IGNORECASE):
                return True

        except re.error:

            if rules.DENY_ON_SECURITY_CHECK_ERROR:
                raise

    return False


# ============================================================
# 보호 파일 검사
# ============================================================

def is_protected_path(path_value: str) -> bool:
    """rules.py의 보호 파일 규칙에 해당하는지 검사합니다."""

    if not path_value:
        return False

    for pattern in rules.PROTECTED_FILE_PATTERNS:

        try:

            if re.search(pattern, path_value, re.IGNORECASE):
                return True

        except re.error:

            if rules.DENY_ON_SECURITY_CHECK_ERROR:
                raise

    return False


def is_security_core_path(path_value: str) -> bool:
    """rules.py의 보안 핵심 파일 규칙에 해당하는지 검사합니다."""

    if not path_value:
        return False

    for pattern in getattr(rules, "SECURITY_CORE_FILE_PATTERNS", []):

        try:

            if re.search(pattern, path_value, re.IGNORECASE):
                return True

        except re.error:

            if rules.DENY_ON_SECURITY_CHECK_ERROR:
                raise

    return False



# ============================================================
# 위험 파일 작업 검사
# ============================================================

def detect_file_operation(
    tool_name: str,
    args: dict
) -> str | None:
    """
    현재 toolCall에서 파일 작업의 성격을 추정합니다.

    중요:
    실제 Antigravity의 tool 이름이 아직 모두 확인되지 않았으므로
    확실하게 식별할 수 있는 경우만 반환합니다.

    반환값:
        delete
        overwrite
        rename
        None
    """

    text_values = collect_strings(args)

    combined_text = " ".join(text_values).lower()
    lowered_tool_name = tool_name.lower()

    # 명시적인 tool 이름
    if "delete" in lowered_tool_name:
        return "delete"

    if "rename" in lowered_tool_name:
        return "rename"

    # 명령형 tool에서 명백한 파일 작업이 표현된 경우
    if re.search(r"\b(del|rm|remove)\b", combined_text):
        return "delete"

    if re.search(r"\b(rename|move|mv)\b", combined_text):
        return "rename"

    return None


# ============================================================
# 파일 경로 검사
# ============================================================

def check_file_paths(
    tool_name: str,
    args: dict,
    command_line: str,
    cwd_value: str
) -> None:
    """
    toolCall 안에서 발견되는 문자열을 대상으로
    민감 파일 / 보호 파일 여부를 검사합니다.

    현재는 '파일처럼 보이는 경로'를 탐지하는 단계입니다.
    실제 파일 수정 tool의 정확한 payload 구조가 확인되면
    더욱 정밀하게 제한할 수 있습니다.
    """

    values = collect_strings(args)

    for value in values:

        # 너무 짧은 문자열은 경로 검사에서 제외
        if len(value) < 3:
            continue

        try:

            if is_sensitive_path(value):

                deny(
                    reason=(
                        "rules.py의 민감 파일 규칙에 "
                        f"해당하는 경로가 발견되었습니다: {value}"
                    ),
                    tool_name=tool_name,
                    command_line=command_line,
                    cwd_value=cwd_value
                )

            if tool_name in {"write_to_file", "replace_file_content", "multi_replace_file_content"}:
                if is_security_core_path(value):
                    deny(
                        reason=(
                            "보안 핵심 파일 수정 시도가 감지되어 "
                            f"차단되었습니다: {value}"
                        ),
                        tool_name=tool_name,
                        command_line=command_line,
                        cwd_value=cwd_value
                    )

            if is_protected_path(value):

                # 보호 파일은 현재 즉시 차단하지 않습니다.
                #
                # 이유:
                # .gemini / .git 등을 포함한 정상적인 작업까지
                # 잘못 차단할 수 있기 때문입니다.
                #
                # 현재는 로그에 기록하고 다음 단계에서
                # 실제 작업 종류와 승인 상태를 함께 판단합니다.

                write_log(
                    tool_name=tool_name,
                    command_line=command_line,
                    cwd_value=cwd_value,
                    decision="protected-detected",
                    reason=(
                        "보호 대상 경로가 감지되었습니다: "
                        f"{value}"
                    )
                )

        except re.error as exc:

            if rules.DENY_ON_SECURITY_CHECK_ERROR:

                deny(
                    reason=(
                        "파일 경로 보안 규칙 검사 중 "
                        f"오류가 발생했습니다: {exc}"
                    ),
                    tool_name=tool_name,
                    command_line=command_line,
                    cwd_value=cwd_value
                )


# ============================================================
# 위험 파일 작업 검사
# ============================================================


# ============================================================
# 작업 영역 경계 검사 (SCOPE)
# ============================================================

def check_workspace_boundary(
    tool_name: str,
    args: dict,
    payload: dict,
    command_line: str,
    cwd_value: str
) -> None:
    """
    명시적 파일 수정 도구 3종(write_to_file, replace_file_content, multi_replace_file_content)에 대해
    TargetFile이 workspacePaths 영역 내에 존재하는지 pathlib 기반으로 검사합니다.
    """

    if tool_name not in {"write_to_file", "replace_file_content", "multi_replace_file_content"}:
        return

    target_file = args.get("TargetFile")
    if not target_file or not isinstance(target_file, str):
        deny(
            reason=f"{tool_name}의 TargetFile 인자를 확인할 수 없어 차단했습니다.",
            tool_name=tool_name,
            command_line=command_line,
            cwd_value=cwd_value
        )

    workspace_paths = payload.get("workspacePaths")
    if not workspace_paths or not isinstance(workspace_paths, list):
        deny(
            reason="workspacePaths 정보를 확인할 수 없어 작업 영역 밖 파일 수정이 차단되었습니다.",
            tool_name=tool_name,
            command_line=command_line,
            cwd_value=cwd_value
        )

    try:
        target_str = target_file.strip()
        p = Path(target_str)
        if not p.is_absolute():
            base_dir = Path(cwd_value) if (cwd_value and os.path.exists(cwd_value)) else Path.cwd()
            p = base_dir / p

        if p.exists():
            resolved_target = p.resolve()
        else:
            parent = p.parent
            if parent.exists():
                resolved_target = parent.resolve() / p.name
            else:
                resolved_target = p.resolve()
    except Exception as exc:
        deny(
            reason=f"대상 경로 정규화 실패로 인해 차단되었습니다: {exc}",
            tool_name=tool_name,
            command_line=command_line,
            cwd_value=cwd_value
        )

    in_bounds = False
    for ws in workspace_paths:
        if not ws or not isinstance(ws, str):
            continue
        try:
            ws_path = Path(ws).resolve()
            target_norm = os.path.normcase(str(resolved_target))
            ws_norm = os.path.normcase(str(ws_path))

            if os.path.commonpath([target_norm, ws_norm]) == ws_norm:
                in_bounds = True
                break
        except Exception:
            continue

    if not in_bounds:
        deny(
            reason=f"작업 영역({workspace_paths}) 밖의 파일 수정이 감지되어 차단되었습니다: {target_file}",
            tool_name=tool_name,
            command_line=command_line,
            cwd_value=cwd_value
        )


def check_file_operation(
    tool_name: str,
    args: dict,
    command_line: str,
    cwd_value: str
) -> None:
    """
    삭제 / 덮어쓰기 / 이름변경 등의 위험 작업을 검사합니다.

    현재는 실제 toolCall 구조가 완전히 확인되지 않았으므로
    명확하게 식별되는 작업만 처리합니다.
    """

    operation = detect_file_operation(
        tool_name=tool_name,
        args=args
    )

    if operation is None:
        return

    # rules.py에 정의된 위험 작업인지 확인
    if not rules.DANGEROUS_FILE_OPERATIONS.get(operation, False):
        return

    # 현재 정책상 삭제는 승인 필요
    if (
        operation == "delete"
        and rules.REQUIRE_APPROVAL_FOR_FILE_DELETION
    ):

        deny(
            reason=(
                "삭제 작업이 감지되었습니다. "
                "승인 상태 확인 전까지 차단합니다."
            ),
            tool_name=tool_name,
            command_line=command_line,
            cwd_value=cwd_value
        )

    # 덮어쓰기 / 이름 변경도 승인 정책이 활성화되어 있으면
    # 현재 단계에서는 안전하게 차단합니다.
    if (
        operation in ("overwrite", "rename")
        and rules.REQUIRE_APPROVAL_FOR_FILE_CHANGES
    ):

        deny(
            reason=(
                f"{operation} 작업이 감지되었습니다. "
                "승인 상태 확인 전까지 차단합니다."
            ),
            tool_name=tool_name,
            command_line=command_line,
            cwd_value=cwd_value
        )


# ============================================================
# 메인
# ============================================================

def main() -> None:

    # --------------------------------------------------------
    # 1. Hook 입력 읽기
    # --------------------------------------------------------

    try:

        payload = json.load(sys.stdin)

    except Exception as exc:

        if rules.DENY_ON_INVALID_HOOK_INPUT:

            deny(
                f"훅 입력 JSON을 해석할 수 없습니다: {exc}"
            )

        allow()


    # --------------------------------------------------------
    # 2. toolCall 확인
    # --------------------------------------------------------

    tool_call = payload.get("toolCall", {})

    if not isinstance(tool_call, dict):

        deny(
            "toolCall 형식이 올바르지 않습니다."
        )


    tool_name = str(
        tool_call.get("name", "")
    )

    args = tool_call.get("args", {})

    if not isinstance(args, dict):

        deny(
            "toolCall args 형식이 올바르지 않습니다.",
            tool_name=tool_name
        )


    # --------------------------------------------------------
    # 3. 명령 / 작업 디렉터리 추출
    # --------------------------------------------------------

    command_line = str(
        args.get("CommandLine", "")
    )

    cwd_value = str(
        args.get("Cwd", "")
    )


    # --------------------------------------------------------
    # 4. 위험 명령 검사
    # --------------------------------------------------------

    check_dangerous_command(
        command_line=command_line,
        tool_name=tool_name,
        cwd_value=cwd_value
    )


    # --------------------------------------------------------
    # 5. 파일 경로 검사
    # --------------------------------------------------------

    check_file_paths(
        tool_name=tool_name,
        args=args,
        command_line=command_line,
        cwd_value=cwd_value
    )


    # --------------------------------------------------------
    # 5.5 작업 영역 경계 검사 (SCOPE)
    # --------------------------------------------------------

    check_workspace_boundary(
        tool_name=tool_name,
        args=args,
        payload=payload,
        command_line=command_line,
        cwd_value=cwd_value
    )



    # --------------------------------------------------------
    # 6. 파일 작업 검사
    # --------------------------------------------------------

    check_file_operation(
        tool_name=tool_name,
        args=args,
        command_line=command_line,
        cwd_value=cwd_value
    )


    # --------------------------------------------------------
    # 7. 모든 현재 검사 통과
    # --------------------------------------------------------

    allow(
        tool_name=tool_name,
        command_line=command_line,
        cwd_value=cwd_value
    )


if __name__ == "__main__":
    main()