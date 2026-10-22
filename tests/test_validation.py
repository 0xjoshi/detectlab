from app.detection.validation import validate_detection


def test_validation_passes_when_expected_rule_detects():
    result = validate_detection(
        expected_rule_id="DET-001",
        detections=[
            {"rule_id": "DET-001", "count": 3},
        ],
    )

    assert result["status"] == "PASS"
    assert result["expected_rule_id"] == "DET-001"
    assert result["matched"] is True


def test_validation_fails_when_expected_rule_does_not_detect():
    result = validate_detection(
        expected_rule_id="DET-001",
        detections=[],
    )

    assert result["status"] == "FAIL"
    assert result["expected_rule_id"] == "DET-001"
    assert result["matched"] is False


def test_validation_fails_when_only_an_unexpected_rule_detects():
    result = validate_detection(
        expected_rule_id="DET-001",
        detections=[
            {"rule_id": "DET-002", "count": 3},
        ],
    )

    assert result["status"] == "FAIL"
    assert result["matched"] is False


def test_validation_rejects_empty_expected_rule_id():
    import pytest

    with pytest.raises(ValueError):
        validate_detection(
            expected_rule_id=" ",
            detections=[],
        )


def test_validation_rejects_invalid_detections_input():
    import pytest

    with pytest.raises(ValueError):
        validate_detection(
            expected_rule_id="DET-001",
            detections="not a list",
        )

def test_validation_passes_when_rule_and_host_match():
    result = validate_detection(
        expected_rule_id="DET-001",
        expected_host="WIN11-LAB",
        detections=[
            {
                "rule_id": "DET-001",
                "count": 3,
                "group": {"host": "WIN11-LAB", "user": "labuser"},
            },
        ],
    )

    assert result["status"] == "PASS"
    assert result["matched"] is True
    assert result["expected_host"] == "WIN11-LAB"


def test_validation_fails_when_rule_matches_but_host_does_not():
    result = validate_detection(
        expected_rule_id="DET-001",
        expected_host="WIN11-LAB",
        detections=[
            {
                "rule_id": "DET-001",
                "count": 3,
                "group": {"host": "UBUNTU-LAB", "user": "labuser"},
            },
        ],
    )

    assert result["status"] == "FAIL"
    assert result["matched"] is False


def test_validation_rejects_empty_expected_host():
    import pytest

    with pytest.raises(ValueError):
        validate_detection(
            expected_rule_id="DET-001",
            expected_host=" ",
            detections=[],
        )
