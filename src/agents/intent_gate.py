"""
Intent Validation Gate
======================
Đây là tuyến phòng thủ đầu tiên trong kiến trúc Orchestrator-Worker.
Nhiệm vụ: Phát hiện và chặn Goal Hijack (OWASP LLM-ASI01) trước khi
bất kỳ LLM worker nào nhận input từ user.

Chiến lược phòng thủ (theo OWASP LLM Top 10):
  - LLM01: Prompt Injection → detect override keywords, role escalation
  - ASI01: Goal Hijack → validate intent fingerprint trước dispatch
  - LLM06: Sensitive Info → sanitize trước khi vào context
"""

import re
import hashlib
from typing import Tuple

# ── Injection signatures ──────────────────────────────────────────────────────
INJECTION_PATTERNS = [
    # Classic override attempts
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
    r"disregard\s+(all\s+)?instructions",
    r"forget\s+(all\s+)?previous\s+(instructions|context|rules)",
    r"new\s+(task|instruction|role|goal)\s*:",
    # Role escalation
    r"you\s+are\s+now\s+(a|an|the)\s+\w+",
    r"act\s+as\s+(a|an|the)\s+\w+",
    r"pretend\s+to\s+be",
    r"your\s+(new\s+)?role\s+is",
    # System prompt extraction
    r"(print|reveal|show|output|repeat|tell me)\s+(your\s+)?(system\s+prompt|instructions|rules)",
    r"what\s+are\s+your\s+(instructions|rules|guidelines)",
    # Goal override
    r"report\s+(that\s+)?(all\s+)?systems?\s+(are\s+)?(clean|safe|secure|ok)",
    r"say\s+(that\s+)?everything\s+is\s+(fine|ok|safe|clean)",
    r"mark\s+(everything|all)\s+as\s+(safe|clean|approved)",
    # Delimiter injection
    r"---+\s*(system|user|assistant)\s*---+",
    r"<\s*(system|user|assistant)\s*>",
    r"\[system\]|\[user\]|\[assistant\]",
    r"###\s*(system|instruction)",
]

# ── Malware name allowlist pattern ────────────────────────────────────────────
# Tên malware hợp lệ thường là: chữ cái, số, dấu gạch ngang, không dấu chấm câu bất thường
SAFE_MALWARE_PATTERN = re.compile(
    r"^[a-zA-Z0-9\s\-_\./\(\)\'\"]{1,120}$"
)

COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in INJECTION_PATTERNS]


def detect_injection(text: str) -> Tuple[bool, str]:
    """
    Returns (is_malicious: bool, matched_pattern: str).
    """
    for pattern in COMPILED_PATTERNS:
        match = pattern.search(text)
        if match:
            return True, f"Pattern matched: '{match.group(0)[:60]}'"
    return False, ""


def sanitize_input(text: str) -> str:
    """
    Strip control characters và các ký tự bất thường có thể dùng để inject.
    Giữ nguyên tên malware hợp lệ.
    """
    # Remove null bytes, non-printable chars
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    # Collapse multiple whitespace
    cleaned = re.sub(r"\s{3,}", " ", cleaned).strip()
    # Limit length
    return cleaned[:200]


def build_intent_fingerprint(malware_name: str) -> str:
    """
    Tạo fingerprint cho intent ban đầu của user.
    Fingerprint này được truyền qua tất cả workers để họ có thể
    verify rằng task nhận được khớp với intent gốc.
    """
    canonical = malware_name.strip().lower()
    digest = hashlib.sha256(canonical.encode()).hexdigest()[:16]
    return f"INTENT:{canonical}:{digest}"


def validate_intent(raw_input: str) -> dict:
    """
    Main validation function. Trả về dict với:
      - intent_valid: bool
      - sanitized_input: str (nếu valid)
      - intent_reason: str (lý do pass/block)
      - attack_detected: bool
      - attack_payload: str (nếu phát hiện tấn công)
      - intent_fingerprint: str (nếu valid)
    """
    # Step 1: Basic sanitize trước khi check
    sanitized = sanitize_input(raw_input)

    if not sanitized:
        return {
            "intent_valid": False,
            "sanitized_input": "",
            "intent_reason": "Empty input after sanitization",
            "attack_detected": False,
            "attack_payload": "",
            "intent_fingerprint": "",
        }

    # Step 2: Detect injection
    is_malicious, matched = detect_injection(raw_input)
    if is_malicious:
        return {
            "intent_valid": False,
            "sanitized_input": "",
            "intent_reason": f"ASI01 Goal Hijack detected — {matched}",
            "attack_detected": True,
            "attack_payload": raw_input[:500],  # capture for forensics
            "intent_fingerprint": "",
        }

    # Step 3: Validate format — phải có vẻ như tên malware thực
    if not SAFE_MALWARE_PATTERN.match(sanitized):
        return {
            "intent_valid": False,
            "sanitized_input": "",
            "intent_reason": "Input contains unsafe characters — possible injection attempt",
            "attack_detected": True,
            "attack_payload": raw_input[:500],
            "intent_fingerprint": "",
        }

    # Step 4: Build intent fingerprint
    fingerprint = build_intent_fingerprint(sanitized)

    return {
        "intent_valid": True,
        "sanitized_input": sanitized,
        "intent_reason": "Input passed all validation checks",
        "attack_detected": False,
        "attack_payload": "",
        "intent_fingerprint": fingerprint,
        "malware_name": sanitized,
    }


def intent_gate_node(state: dict) -> dict:
    """
    LangGraph node: Intent Validation Gate.
    Đây là node đầu tiên trong graph — không có LLM, pure Python.
    """
    raw = state.get("raw_user_input", state.get("malware_name", ""))
    result = validate_intent(raw)

    print(f"\n[INTENT GATE] Input: '{raw[:60]}...' → Valid: {result['intent_valid']}")
    if result["attack_detected"]:
        print(f"[INTENT GATE] ⚠️  ATTACK DETECTED: {result['intent_reason']}")

    return result
