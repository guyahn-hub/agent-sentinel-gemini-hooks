#!/usr/bin/env python3
"""
스모크 테스트용 훅 스크립트.
이 훅이 실제로 호출되면 smoke_test.log에 한 줄이 남는다.
로그가 안 쌓이면 -> 이 이벤트는 현재 Antigravity 버전에서 발화하지 않는다는 뜻.
"""
import sys
import json
import datetime
import os

LOG_PATH = os.path.join(os.path.dirname(__file__), "smoke_test.log")

try:
    raw = sys.stdin.read()
except Exception:
    raw = "(stdin 읽기 실패)"

try:
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(f"{datetime.datetime.now().isoformat()} | hook fired | payload={raw[:500]}\n")
except Exception as e:
    # 로그 기록 자체가 실패해도 훅 응답은 정상적으로 내보낸다
    sys.stderr.write(f"로그 기록 실패: {e}\n")

# PreToolUse처럼 decision이 필요한 이벤트를 위해 항상 allow를 출력
print(json.dumps({"decision": "allow"}))
