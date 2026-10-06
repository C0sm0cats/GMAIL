import email
import os
import sys
import unittest
from email.policy import default as policy_default

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import savegmail  # noqa: E402

from prompt_toolkit.application import create_app_session  # noqa: E402
from prompt_toolkit.input import create_pipe_input  # noqa: E402
from prompt_toolkit.output import DummyOutput  # noqa: E402


def make_messages(count):
    return [
        {"id": str(i), "from": f"Sender {i} <s{i}@example.com>", "subject": f"Subject {i}",
         "snippet": "snippet", "internalDate": 1_700_000_000_000 + i, "attachment": i == 0}
        for i in range(count)
    ]


def pick(keys, messages=None, **kwargs):
    messages = make_messages(3) if messages is None else messages
    with create_pipe_input() as pipe:
        pipe.send_text(keys)
        with create_app_session(input=pipe, output=DummyOutput()):
            action, chosen = savegmail.pick_messages(messages, **kwargs)
    return action, [message["id"] for message in chosen]


class ParseSelectionTest(unittest.TestCase):
    def test_numbers_ranges_and_all(self):
        self.assertEqual(savegmail.parse_selection("1, 3 5-4", 5), [0, 2, 3, 4])
        self.assertEqual(savegmail.parse_selection("all", 3), [0, 1, 2])
        self.assertEqual(savegmail.parse_selection("q", 3), [])

    def test_invalid(self):
        with self.assertRaises(ValueError):
            savegmail.parse_selection("9", 3)
        with self.assertRaises(ValueError):
            savegmail.parse_selection("x", 3)

    def test_action_prefix(self):
        self.assertEqual(savegmail.parse_command("d 1,3"), ("trash", "1,3"))
        self.assertEqual(savegmail.parse_command("S all"), ("save", "all"))
        self.assertEqual(savegmail.parse_command("1-2"), ("download", "1-2"))
        self.assertEqual(savegmail.parse_command("D 2"), ("delete", "2"))


class TextHelpersTest(unittest.TestCase):
    def test_fit_pads_and_truncates(self):
        self.assertEqual(savegmail.fit("ab", 4), "ab  ")
        self.assertEqual(savegmail.fit("abcdef", 4), "abc…")
        self.assertEqual(savegmail.fit("a\n  b", 3), "a b")

    def test_html_to_text(self):
        text = savegmail.html_to_text("<html><style>p{}</style><p>Hello&nbsp;<b>you</b></p><br>Bye</html>")
        self.assertEqual(text, "Hello you\n\nBye")

    def test_message_text_prefers_plain(self):
        msg = email.message.EmailMessage(policy=policy_default)
        msg.set_content("plain body")
        msg.add_alternative("<p>html body</p>", subtype="html")
        self.assertEqual(savegmail.message_text(msg), "plain body")

    def test_attachment_flag(self):
        detail = {"id": "1", "payload": {"mimeType": "multipart/mixed", "headers": []}}
        self.assertTrue(savegmail.to_candidate(detail)["attachment"])
        detail["payload"]["mimeType"] = "multipart/alternative"
        self.assertFalse(savegmail.to_candidate(detail)["attachment"])


class FakeRequest:
    def __init__(self, msg_id, failures):
        self.msg_id, self.failures = msg_id, failures

    def execute(self):
        if self.failures.get(self.msg_id, 0) > 0:
            self.failures[self.msg_id] -= 1
            raise RuntimeError(f"boom {self.msg_id}")
        return {"id": self.msg_id}


class FakeBatch:
    def __init__(self, callback, sizes):
        self.callback, self.items, self.sizes = callback, [], sizes

    def add(self, request, request_id):
        self.items.append((request, request_id))

    def execute(self):
        self.sizes.append(len(self.items))
        for request, request_id in self.items:
            try:
                self.callback(request_id, request.execute(), None)
            except Exception as exc:
                self.callback(request_id, None, exc)


class FakeService:
    def __init__(self):
        self.sizes = []

    def new_batch_http_request(self, callback):
        return FakeBatch(callback, self.sizes)


class RunBatchedTest(unittest.TestCase):
    def test_batches_and_retries(self):
        service = FakeService()
        ids = [str(i) for i in range(120)]
        failures = {"3": 1, "7": 2}  # 3 recovers on retry, 7 keeps failing
        responses, errors = savegmail.run_batched(service, ids, lambda msg_id: FakeRequest(msg_id, failures))
        self.assertEqual(service.sizes, [50, 50, 20])
        self.assertEqual(set(errors), {"7"})
        self.assertEqual(len(responses), 119)


class PickerTest(unittest.TestCase):
    def test_enter_downloads_current(self):
        self.assertEqual(pick("\r"), ("download", ["0"]))

    def test_save_selection(self):
        self.assertEqual(pick(" j s"), ("save", ["0", "2"]))

    def test_trash_needs_confirmation(self):
        self.assertEqual(pick("dy"), ("trash", ["0"]))
        self.assertEqual(pick("dnq"), ("quit", []))
        self.assertEqual(pick("dn\r"), ("download", ["0"]))

    def test_delete_needs_typed_confirmation(self):
        self.assertEqual(pick("Ddelete\r"), ("delete", ["0"]))
        self.assertEqual(pick("Dy\rq"), ("quit", []))
        self.assertEqual(pick("Ddel\x1bq"), ("quit", []))
        self.assertEqual(pick("Ddelx\x7f\x7f\x7f\x7f\x7f\x7fdelete\r"), ("delete", ["0"]))

    def test_trash_selection(self):
        self.assertEqual(pick("ady"), ("trash", ["0", "1", "2"]))

    def test_preview_uses_cursor_not_selection(self):
        self.assertEqual(pick(" p"), ("preview", ["1"]))

    def test_undo_only_when_available(self):
        self.assertEqual(pick("uq"), ("quit", []))
        self.assertEqual(pick("u", can_undo=True), ("undo", []))

    def test_filter(self):
        self.assertEqual(pick("/Subject 2\r\r"), ("download", ["2"]))

    def test_state_survives_runs(self):
        state = savegmail.new_picker_state()
        self.assertEqual(pick(" jq", state=state), ("quit", []))
        self.assertEqual(state["selected"], {"0"})
        self.assertEqual(pick("s", state=state), ("save", ["0"]))

    def test_load_more_prepends_older(self):
        messages = make_messages(2)
        older = [{**make_messages(1)[0], "id": "old", "internalDate": 1}]
        action, ids = pick("m\r", messages, load_more=lambda: (older, False))
        self.assertEqual([message["id"] for message in messages], ["old", "0", "1"])


if __name__ == "__main__":
    unittest.main()
