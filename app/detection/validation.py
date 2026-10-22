
from typing import Any


def validate_detection(
    expected_rule_id: str,
    detections: list[dict[str, Any]],
    expected_host: str | None = None,
) -> dict[str, Any]:
    """Validate that an expected rule detected on the expected host."""

    if not isinstance(expected_rule_id, str) or not expected_rule_id.strip():
        raise ValueError("expected_rule_id must be a non-empty string.")

    if expected_host is not None:
        if not isinstance(expected_host, str) or not expected_host.strip():
            raise ValueError("expected_host must be a non-empty string.")

    if not isinstance(detections, list):
        raise ValueError("detections must be a list.")

    for detection in detections:
        if not isinstance(detection, dict):
            raise ValueError("Each detection must be a dictionary.")

    matched = any(
        detection.get("rule_id") == expected_rule_id
        and (
            expected_host is None
            or (
                isinstance(detection.get("group"), dict)
                and detection["group"].get("host") == expected_host
            )
        )
        for detection in detections
    )

    result = {
        "status": "PASS" if matched else "FAIL",
        "expected_rule_id": expected_rule_id,
        "matched": matched,
    }

    if expected_host is not None:
        result["expected_host"] = expected_host

    return result
