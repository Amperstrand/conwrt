from __future__ import annotations

import json
from argparse import Namespace
from unittest.mock import patch


from conwrt.cmd_info import cmd_list


class TestCmdListEmpty:
    @patch("conwrt.cmd_info.list_models", return_value=[])
    def test_returns_1_when_no_models(self, mock_list, capsys):
        result = cmd_list(Namespace())
        assert result == 1
        captured = capsys.readouterr()
        assert "No models found" in captured.err


class TestCmdListWithModels:
    @patch(
        "conwrt.cmd_info.list_models",
        return_value=[
            {
                "id": "test-device-v1",
                "vendor": "TestCorp",
                "openwrt": {"target": "testarch/testsub"},
                "flash_methods": {"sysupgrade": {}},
                "description": "A test device",
            }
        ],
    )
    def test_returns_0_and_prints_table(self, mock_list, capsys):
        result = cmd_list(Namespace())
        assert result == 0
        captured = capsys.readouterr()
        assert "test-device-v1" in captured.out
        assert "TestCorp" in captured.out
        assert "sysupgrade" in captured.out
        assert "1 model(s) valid in models" in captured.out  # `conwrt models` footer shape

    @patch(
        "conwrt.cmd_info.list_models",
        return_value=[
            {
                "id": "sort-device-v1",
                "vendor": "TestCorp",
                "openwrt": {"target": "testarch/testsub"},
                # insertion order deliberately non-alphabetical: `conwrt models` sorts (BTreeMap)
                "flash_methods": {"zycast": {}, "sysupgrade": {}, "recovery-http": {}},
                "description": "A test device",
            }
        ],
    )
    def test_flash_methods_sorted_rust_shape(self, mock_list, capsys):
        result = cmd_list(Namespace())
        assert result == 0
        out = capsys.readouterr().out
        assert "[recovery-http, sysupgrade, zycast]" in out

    @patch(
        "conwrt.cmd_info.list_models",
        return_value=[
            {
                "id": "bare-model",
                "vendor": "V",
                "openwrt": {},
                "description": "",
            }
        ],
    )
    def test_handles_missing_flash_methods(self, mock_list, capsys):
        result = cmd_list(Namespace())
        assert result == 0
        captured = capsys.readouterr()
        assert "bare-model" in captured.out
        assert "[]" in captured.out  # `conwrt models` renders empty set as []; schema forbids it in-corpus


