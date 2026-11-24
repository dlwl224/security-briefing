"""Gemini 호출 실패 시 다음 모델로 넘어가는지 확인."""

import json
import os
import unittest
from unittest import mock

import requests

from briefing import llm


def _ok(payload: dict) -> mock.Mock:
    body = {"candidates": [{"content": {"parts": [{"text": json.dumps(payload)}]}}]}
    return mock.Mock(status_code=200, json=mock.Mock(return_value=body), text="")


def _err(status: int) -> mock.Mock:
    return mock.Mock(status_code=status, text="error")


@mock.patch.dict(os.environ, {"GEMINI_API_KEY": "test"})
@mock.patch.object(llm.time, "sleep")
@mock.patch.object(llm, "MODELS", ["a", "b", "c"])
class CallFallbackTest(unittest.TestCase):
    def test_timeout_moves_to_next_model(self, _sleep):
        with mock.patch.object(llm.requests, "post", side_effect=[requests.Timeout(), _ok({"x": 1})]) as post:
            self.assertEqual(llm._call("p", {}), {"x": 1})
        self.assertIn("/b:", post.call_args.args[0])

    def test_not_found_moves_to_next_model(self, _sleep):
        with mock.patch.object(llm.requests, "post", side_effect=[_err(404), _ok({"x": 2})]):
            self.assertEqual(llm._call("p", {}), {"x": 2})

    def test_overload_retries_then_falls_back(self, sleep):
        side = [_err(503), _err(503), _err(503), _ok({"x": 3})]
        with mock.patch.object(llm.requests, "post", side_effect=side):
            self.assertEqual(llm._call("p", {}), {"x": 3})
        self.assertEqual(sleep.call_count, 3)

    def test_invalid_json_moves_to_next_model(self, _sleep):
        bad = mock.Mock(status_code=200, json=mock.Mock(return_value={"candidates": []}), text="")
        with mock.patch.object(llm.requests, "post", side_effect=[bad, _ok({"x": 4})]):
            self.assertEqual(llm._call("p", {}), {"x": 4})

    def test_all_models_fail_raises(self, _sleep):
        with mock.patch.object(llm.requests, "post", side_effect=requests.Timeout()):
            with self.assertRaises(RuntimeError):
                llm._call("p", {})


if __name__ == "__main__":
    unittest.main()
