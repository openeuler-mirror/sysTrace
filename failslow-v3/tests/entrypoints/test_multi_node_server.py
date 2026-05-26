import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

import pytest

from failslow.entrypoints import multi_node_server


def test_main_rejects_detect_interval_argument(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "systrace-failslow-server",
            "--config",
            "config.json",
            "--detect-interval",
            "12",
        ],
    )

    with pytest.raises(SystemExit) as exc_info:
        multi_node_server.main()

    assert exc_info.value.code == 2
