# Agent Sentinel — Gemini Hooks

**A practical security and audit layer for AI coding agents using Gemini Hooks.**

> **Don't trust what the agent says it did. Check what it actually did.**

Agent Sentinel is an experimental, Windows-focused security layer built around Gemini Hooks. It places a lightweight gate in front of tool execution and a protocol audit after the agent finishes its work.

The project started from a simple problem:

**An AI coding agent can be capable of performing useful work, but capability without boundaries can also mean unintended file access, scope violations, or incomplete verification.**

Instead of trying to build a large security framework, Agent Sentinel takes a narrower approach:

```text
        AI Agent
           │
           ▼
     PreToolUse Gate
           │
      ┌────┴────┐
      │         │
    allow     deny
      │
      ▼
   Tool Work
      │
      ▼
  Transcript Log
      │
      ▼
    Stop Hook
      │
      ▼
 Protocol Audit
      │
   ┌──┴──┐
 allow  continue
```

## What it does

### 1. PreToolUse protection

`security_gate.py` runs before a tool is executed.

The current implementation checks for things such as:

- dangerous command patterns
- sensitive/protected paths
- attempts to modify security-core files
- workspace boundary violations
- path traversal
- Windows case-insensitive path handling
- symbolic-link / junction boundary cases
- selected dangerous file operations

The actual policy definitions are kept in `rules.py` rather than being scattered throughout the hook implementation.

### 2. Workspace boundary enforcement

For the explicit file-modification tools currently handled by the gate:

- `write_to_file`
- `replace_file_content`
- `multi_replace_file_content`

`TargetFile` is checked against the `workspacePaths` supplied by the hook payload.

The gate fails closed when the workspace information required for the check is unavailable.

### 3. Post-work audit

`protocol_manager.py` runs at the `Stop` stage.

Instead of trusting the agent's final message, it reads the actual `transcript.jsonl` and evaluates the recorded tool-call trajectory against audit rules declared in `GEMINI.md`.

The current audit rules cover concepts such as:

- required inspection before modification
- required verification after modification
- workspace/scope verification

The audit result is returned as either:

```text
allow
```

or

```text
continue
```

### 4. GEMINI.md as the audit policy source

The design separates human-readable operating instructions from machine-readable audit rules.

`GEMINI.md` contains the normal agent workflow and an `AUDIT_CONFIG` block that `protocol_manager.py` can parse dynamically.

```text
GEMINI.md
   ├── Human-readable SOP
   └── AUDIT_CONFIG
          ↓
   Protocol Manager
          ↓
   transcript.jsonl
```

This means the audit policy does not have to be duplicated inside `protocol_manager.py`.

## Design principle

The central idea is simple:

> **The agent's explanation is not the evidence. The tool-call trajectory is.**

For example:

```text
Agent: "I checked the file and verified the change."

                 ≠

Transcript:
  view_file
  write_to_file
  run_command
```

Agent Sentinel is designed to evaluate the second one.

## Project structure

```text
agent-sentinel-gemini-hooks/
├── hooks.json
├── README.md
└── hooks-scripts/
    ├── protocol_manager.py
    ├── README.txt
    ├── rules.py
    ├── security_gate.py
    └── smoke_test.py
```

## Current status

**Experimental / early-stage.**

This repository is a working implementation and a record of an evolving security approach, not a finished security product.

The core flow has been exercised with tests covering areas including:

- `AUDIT_CONFIG` parsing
- Protocol Manager execution
- successful audit → `allow`
- missing `workspacePaths` → `continue`
- workspace-internal vs. external paths
- path traversal
- symbolic-link / junction boundary handling
- Windows path case handling
- security-core file protection
- protected/sensitive file detection

These tests demonstrate the current behavior; they should not be interpreted as a claim of complete security coverage.

## Important limitations

This project deliberately does **not** attempt to solve every agent-security problem.

In particular, it is not currently:

- a complete OS-level sandbox
- a zero-trust identity/authentication system
- a replacement for endpoint security software
- a guarantee against every possible shell or tool-level bypass
- a production-ready security product

The current implementation focuses on a practical Hook-based control and audit layer.

## Installation concept

The current configuration is written for a Windows Gemini/Antigravity environment.

`hooks.json` connects the two main stages:

```text
PreToolUse → security_gate.py
Stop       → protocol_manager.py
```

The example configuration contains local Windows paths and therefore must be adapted to the local installation path before use on another machine.

The scripts use Python's standard library; no third-party Python package is required by the current implementation.

## Why this exists

AI coding agents are increasingly able to inspect files, modify code, execute commands, and operate across a project with very little human intervention.

That creates a useful engineering question:

**How do we give an agent enough freedom to work while still having a concrete boundary around what it can touch and a way to verify what it actually did?**

Agent Sentinel is one small experiment toward that answer:

```text
Before the action → Gate it.
During the work  → Record it.
After the work   → Audit it.
```

## Contributing / feedback

This project is intentionally being developed in the open.

If you find a bypass, an incorrect block, a false positive, or a better way to verify agent behavior, issues and practical feedback are welcome.

The goal is not to pretend that the first implementation is perfect. The goal is to make the security boundary **observable, testable, and progressively harder to bypass.**

## License

License and contribution policy are not finalized yet.
