# Hooks / Sentinel Security Gate

Gemini CLI의 작업 과정에서 위험한 파일 접근 및 작업 범위를 사전에 통제하고, 작업 종료 후 실제 Tool 호출 기록을 기반으로 작업 절차 준수 여부를 감사하는 보안 시스템입니다.

## 1. 목적

이 시스템의 목적은 다음과 같습니다.

* Gemini 작업의 **Workspace 범위 이탈 방지**
* 민감하거나 보호해야 할 파일의 **직접 수정 차단**
* 위험한 작업에 대한 **PreToolUse 사전 차단**
* 작업 종료 후 실제 `transcript.jsonl`을 기반으로 **작업 절차 감사**
* `GEMINI.md`에 정의된 감사 규칙과 실제 작업 기록의 연결
* AI가 작업 완료라고 설명한 내용이 아니라 **실제 Tool 호출 기록을 기준으로 검증**

핵심 원칙:

> **AI의 설명을 신뢰하는 것이 아니라 실제 작업 기록과 실행 결과를 기준으로 검증한다.**

---

## 2. 전체 구조

```text
GEMINI.md
   │
   ├─ 작업 절차 / SOP
   └─ AUDIT_CONFIG
          │
          ▼
      Gemini 작업
          │
          ├───────────────┐
          ▼               ▼
    PreToolUse           Tool 실행
          │               │
          ▼               ▼
 security_gate.py    transcript.jsonl
          │
          ▼
      rules.py
          │
      허용 / 차단
          
작업 종료
   │
   ▼
Stop Hook
   │
   ▼
protocol_manager.py
   │
   ▼
transcript.jsonl 분석
   │
   ▼
AUDIT_CONFIG 평가
   │
   ├─ allow
   └─ continue
```

---

## 3. 주요 파일

### `security_gate.py`

PreToolUse Hook입니다.

작업 실행 전에 위험 요소를 검사합니다.

주요 검사:

* 위험한 명령어
* 보호된 파일 접근
* Workspace 외부 경로 접근
* `../` 등을 이용한 경로 탈출
* 심볼릭 링크 / Junction을 통한 Workspace 경계 우회
* 보안 핵심 파일 수정
* 민감 파일 수정

주요 로그:

```text
security_gate.log
```

---

### `rules.py`

보안 규칙을 정의하고 판정하는 모듈입니다.

`security_gate.py`에서 import되어 사용됩니다.

예:

* Workspace 경계 규칙
* Security Core 파일 보호 규칙
* 민감 파일 규칙
* 경로 판정 함수

독립적으로 실행되는 Hook 프로세스가 아니므로 별도의 `rules.log`는 생성하지 않습니다.

---

### `protocol_manager.py`

Stop Hook에서 작업 종료 후 실행되는 감사 모듈입니다.

`GEMINI.md`의 `AUDIT_CONFIG`를 읽고 실제 `transcript.jsonl`의 Tool 호출 기록을 검사합니다.

현재 감사 대상에는 다음과 같은 항목이 포함됩니다.

* 작업 전 필요한 확인이 있었는가
* 작업 후 검증이 수행되었는가
* Workspace / Scope 정보가 확인 가능한가

감사 결과:

```text
allow
```

또는

```text
continue
```

주요 로그:

```text
protocol_manager.log
```

---

### `GEMINI.md`

Gemini 작업의 기본 작업 매뉴얼(SOP)입니다.

사람이 읽는 작업 절차와 함께, Protocol Manager가 기계적으로 평가할 수 있는 `AUDIT_CONFIG`를 포함합니다.

즉:

```text
GEMINI.md
= 사람이 읽는 작업 규칙
+ 기계가 읽는 감사 규칙
```

---

### `hooks.json`

Gemini Hook 연결 설정입니다.

현재 핵심 연결:

```text
PreToolUse → security_gate.py
Stop       → protocol_manager.py
```

---

## 4. 보안 핵심 파일

다음 파일은 Security Core로 취급합니다.

```text
security_gate.py
rules.py
protocol_manager.py
hooks.json
GEMINI.md
```

일반적인 파일 수정 Tool을 통한 직접 수정은 차단하도록 구성되어 있습니다.

보안 시스템 자체를 수정해야 하는 경우에는 별도의 관리 절차가 필요합니다.

---

## 5. 감사 방식

Protocol Manager는 AI의 최종 답변을 기준으로 작업 완료 여부를 판단하지 않습니다.

실제 작업 과정에서 기록된:

```text
transcript.jsonl
```

의 Tool 호출 기록을 기준으로 판단합니다.

예:

```text
파일 확인
   ↓
파일 수정
   ↓
실행 / 검증
   ↓
작업 종료
   ↓
Stop Hook
   ↓
실제 Tool 호출 기록 감사
```

따라서 다음과 같은 차이가 중요합니다.

```text
AI가 "검증했습니다."
        ≠
실제로 검증 Tool이 호출되었습니다.
```

이 시스템은 후자를 확인하는 것을 목표로 합니다.

---

## 6. 현재 검증된 항목

현재까지 다음 항목을 테스트했습니다.

* `AUDIT_CONFIG` 정상 파싱
* Protocol Manager 정상 실행
* 정상적인 감사 조건에서 `allow`
* 필요한 `workspacePaths`가 없는 경우 `continue`
* Workspace 내부 경로 허용
* Workspace 외부 경로 차단
* 경로 traversal 차단
* 심볼릭 링크 / Junction을 통한 경계 우회 검사
* Windows 경로 대소문자 처리
* Security Core 파일 보호
* `.env` 등 보호 파일 접근 차단

---

## 7. 로그 파일

현재 주요 로그:

```text
security_gate.log
protocol_manager.log
smoke_test.log
```

`rules.py`는 독립 프로세스가 아니라 규칙 모듈이므로 별도의 로그 파일이 없는 것이 정상입니다.

Python 실행 과정에서 생성되는:

```text
__pycache__
```

역시 정상적인 Python 동작 결과입니다.

---

## 8. 현재 시스템의 역할

이 시스템은 완전한 운영체제 수준의 보안 시스템이나 사용자 인증 시스템이 아닙니다.

목적은 보다 현실적인 수준에서 다음 구조를 만드는 것입니다.

```text
[작업 전]
위험한 행동 차단
        ↓
[작업 중]
실제 Tool 호출 기록
        ↓
[작업 후]
실제 작업 과정 감사
```

즉,

> **사전 차단 + 실제 작업 기록 + 사후 감사**

를 하나의 Hook 기반 보호 계층으로 구성합니다.

---

## 9. 운영 원칙

보안 시스템 자체를 불필요하게 복잡하게 만들지 않습니다.

특히 다음을 기본 원칙으로 합니다.

1. 실제 필요한 보안 규칙만 추가한다.
2. 이미 검증된 보안 Core를 불필요하게 수정하지 않는다.
3. AI의 설명보다 실제 파일과 Tool 호출 기록을 우선한다.
4. 새로운 기능은 실제 필요성이 확인된 경우에만 추가한다.
5. 테스트용 코드나 로그를 불필요하게 남기지 않는다.
6. 보안 시스템의 변경은 반드시 실제 동작을 다시 검증한다.

---

## 10. 현재 상태

**1차 구현 완료.**

현재 시스템은 다음 목적을 충족합니다.

```text
Gemini 작업
    ↓
PreToolUse 보안 검사
    ↓
위험 작업 차단
    ↓
실제 Tool 호출 기록
    ↓
Stop Hook
    ↓
AUDIT_CONFIG 기반 사후 감사
    ↓
allow / continue
```

추가 기능은 실제 운영 중 필요한 문제가 확인된 이후 검토합니다.
