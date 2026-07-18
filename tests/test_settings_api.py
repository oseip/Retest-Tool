"""Settings validation — duplicate client labels."""

import pytest
from fastapi import HTTPException

from src.settings_api import _reject_duplicate_labels


class TestDuplicateLabels:
    def test_unique_labels_ok(self):
        _reject_duplicate_labels(["ClientA", "ClientB"], "Axian")

    def test_duplicate_raises(self):
        with pytest.raises(HTTPException) as exc:
            _reject_duplicate_labels(["YasTG", "YasTG"], "Non-Axian")
        assert exc.value.status_code == 400
        assert "Duplicate Non-Axian client label" in exc.value.detail
        assert "YasTG" in exc.value.detail
