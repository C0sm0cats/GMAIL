import os
import sys
import unittest

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

    def test_draft(self):
        detail = {"id": "1", "labelIds": ["DRAFT"], "payload": {"headers": [{"name": "From", "value": "Me <me@x>"}]}}
        row = savegmail.message_row(savegmail.to_candidate(detail))
        self.assertEqual(row["sender"], "Draft")
        self.assertIn("draft", row["haystack"])
        detail["labelIds"] = ["INBOX"]
        self.assertEqual(savegmail.message_row(savegmail.to_candidate(detail))["sender"], "Me")

    def test_sent_category_size_flags(self):
        detail = {"id": "1", "labelIds": ["SENT", "UNREAD", "STARRED", "CATEGORY_PROMOTIONS"], "sizeEstimate": 12_400_000,
                  "payload": {"headers": [{"name": "To", "value": "Paul Martin <p@x>, Jo <j@x>"}]}}
        row = savegmail.message_row(savegmail.to_candidate(detail))
        self.assertEqual((row["sender"], row["kind"]), ("Sent · Paul Martin", "sent"))
        self.assertTrue(row["unread"] and row["starred"])
        self.assertEqual(row["tags"], [("category", "Promotions")])
        self.assertEqual((row["size"], row["big"], row["party"]), ("12 MB", True, "p@x"))
        self.assertIn("promotions", row["haystack"])
        savegmail.ACCOUNT = "me@x"
        detail["payload"]["headers"] = [{"name": "To", "value": "Me <ME@x>"}]
        self.assertEqual(savegmail.message_row(savegmail.to_candidate(detail))["sender"], "Sent · me")
        savegmail.ACCOUNT = None
        detail.update(labelIds=["INBOX"], sizeEstimate=20_000)
        row = savegmail.message_row(savegmail.to_candidate(detail))
        self.assertEqual((row["tags"], row["unread"], row["starred"]), ([], False, False))

    def test_user_labels(self):
        savegmail.USER_LABELS = {"Label_1": "Factures", "Label_2": "Pro"}
        try:
            detail = {"id": "1", "labelIds": ["INBOX", "Label_2", "Label_1", "CATEGORY_UPDATES"], "payload": {"headers": []}}
            row = savegmail.message_row(savegmail.to_candidate(detail))
            self.assertEqual(row["tags"], [("category", "Updates"), ("label", "Factures"), ("label", "Pro")])
            self.assertIn("factures", row["haystack"])
        finally:
            savegmail.USER_LABELS = {}

    def test_human_size(self):
        self.assertEqual([savegmail.human_size(size) for size in (300, 820_400, 1_240_000, 123_000_000)],
                         ["1 KB", "820 KB", "1.2 MB", "123 MB"])
        self.assertTrue(all(len(savegmail.human_size(size)) <= savegmail.SIZE_W
                            for size in (999_499, 999_999, 9_949_999, 9_999_999, 999_499_999, 999_999_999, 9_940_000_000)))

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


class FakeListService(FakeService):
    """Gmail list (newest first, paged) + metadata, for refresh_messages."""

    def __init__(self, mailbox):
        super().__init__()
        self.mailbox = mailbox  # [(id, internalDate)] newest first

    def users(self):
        return self

    def messages(self):
        return self

    def list(self, userId, q, maxResults, pageToken=None):
        start = int(pageToken or 0)
        page = self.mailbox[start:start + maxResults]
        response = {"messages": [{"id": msg_id} for msg_id, _ in page]}
        if start + maxResults < len(self.mailbox):
            response["nextPageToken"] = str(start + maxResults)
        return FakeResult(response)

    def get(self, userId, id, format, metadataHeaders, fields):
        return FakeResult({"id": id, "internalDate": dict(self.mailbox)[id], "payload": {"headers": []}})


class FakeResult:
    def __init__(self, value):
        self.value = value

    def execute(self):
        return self.value


class RefreshTest(unittest.TestCase):
    def loaded(self, *pairs):
        return [{"id": msg_id, "internalDate": date} for msg_id, date in pairs]

    def test_new_and_gone(self):
        # Loaded: c(30) b(20) a(10). Since: n(40) arrived, b was deleted; z(5) is older, not loaded yet.
        service = FakeListService([("n", 40), ("c", 30), ("a", 10), ("z", 5)])
        new, gone = savegmail.refresh_messages(service, "me", "", self.loaded(("c", 30), ("b", 20), ("a", 10)),
                                               since=10, page_size=2)
        self.assertEqual([message["id"] for message in new], ["n"])
        self.assertEqual(gone, {"b"})

    def test_oldest_loaded_deleted(self):
        service = FakeListService([("n", 40), ("c", 30), ("z", 5), ("y", 4)])
        new, gone = savegmail.refresh_messages(service, "me", "", self.loaded(("c", 30), ("b", 20), ("a", 10)),
                                               since=10, page_size=2)
        self.assertEqual(([message["id"] for message in new], gone), (["n"], {"b", "a"}))

    def test_whole_view_when_nothing_older_to_load(self):
        # An email older than everything loaded (e.g. restored from the trash) shows up when since=None.
        service = FakeListService([("c", 30), ("a", 10), ("z", 5)])
        new, gone = savegmail.refresh_messages(service, "me", "", self.loaded(("c", 30), ("a", 10)), page_size=2)
        self.assertEqual(([message["id"] for message in new], gone), (["z"], set()))

    def test_up_to_date_skips_older_metadata(self):
        service = FakeListService([("c", 30), ("a", 10), ("z", 5), ("y", 4)])
        new, gone = savegmail.refresh_messages(service, "me", "", self.loaded(("c", 30), ("a", 10)), since=10,
                                               page_size=10)
        self.assertEqual((new, gone), ([], set()))
        self.assertEqual(service.sizes, [])  # z and y are older than the loaded range: no metadata fetched


class FakeBadgeService(FakeService):
    def __init__(self, matches=1):
        super().__init__()
        self.searches, self.matches = [], matches

    def users(self):
        return self

    def labels(self):
        return self

    def messages(self):
        return self

    def get(self, userId, id):
        counters = {"INBOX": (12, 500), "STARRED": (2, 9), "SPAM": (0, 3), "DRAFT": (0, 1), "SENT": (0, 340),
                    "TRASH": (5, 0)}
        unread, total = counters[id]
        return FakeResult({"id": id, "messagesUnread": unread, "messagesTotal": total})

    def list(self, userId, q, maxResults, pageToken=None, fields=None, includeSpamTrash=False):
        self.searches.append((q, includeSpamTrash))
        start = int(pageToken or 0)
        page = min(maxResults, self.matches - start)
        response = {"messages": [{"id": str(i)} for i in range(start, start + page)]}
        if start + page < self.matches:
            response["nextPageToken"] = str(start + page)
        return FakeResult(response)


class BadgeTest(unittest.TestCase):
    QUERIES = {name: query for name, query in savegmail.VIEWS}

    def test_label_counters(self):
        service = FakeBadgeService(matches=1)
        badges = savegmail.view_badges(service, "me", self.QUERIES, filtered=False)
        # Unread everywhere (Trash too), a total for Drafts only; zero counts (Sent, Spam) hidden.
        self.assertEqual(badges, {"Inbox": ("12", "unread"), "Starred": ("2", "unread"), "Drafts": ("1", "total"),
                                  "Trash": ("5", "unread"), "All mail": ("1", "unread"), "Archived": ("1", "unread")})
        self.assertEqual(service.searches, [("is:unread", False), (self.QUERIES["Archived"] + " is:unread", False)])

    def test_exact_count_capped(self):
        service = FakeBadgeService(matches=1500)
        self.assertEqual(savegmail.count_messages(service, "me", "x"), savegmail.BADGE_COUNT_CAP)
        self.assertEqual(savegmail.badge_text(savegmail.BADGE_COUNT_CAP), "1,000+")
        self.assertEqual(savegmail.count_messages(FakeBadgeService(matches=201), "me", "x"), 201)

    def test_filtered_views_use_searches(self):
        service = FakeBadgeService()
        queries = {name: f"(from:x) {query}".strip() for name, query in savegmail.VIEWS}
        savegmail.view_badges(service, "me", queries, filtered=True)
        self.assertIn(("(from:x) in:spam is:unread", True), service.searches)
        self.assertIn(("(from:x) in:trash is:unread", True), service.searches)
        self.assertIn(("(from:x) in:sent is:unread", False), service.searches)
        self.assertIn(("(from:x) in:drafts", False), service.searches)
        self.assertEqual(service.sizes, [])  # no label counters: they ignore --query


class FakeLabelService(FakeService):
    def __init__(self, labels):
        super().__init__()
        self.labels, self.modified = labels, []

    def users(self):
        return self

    def messages(self):
        return self

    def get(self, userId, id, format, fields):
        return FakeResult({"id": id, "labelIds": list(self.labels[id])})

    def batchModify(self, userId, body):
        self.modified.append(body)
        return FakeResult({})


class ReadStateTest(unittest.TestCase):
    def test_refresh_labels(self):
        service = FakeLabelService({"1": ["INBOX"], "2": ["INBOX", "UNREAD"]})
        loaded = [{"id": "1", "labels": ["INBOX", "UNREAD"]}, {"id": "2", "labels": ["INBOX", "UNREAD"]}]
        self.assertEqual(savegmail.refresh_labels(service, "me", loaded), 1)  # 1 was read elsewhere
        self.assertEqual(loaded[0]["labels"], ["INBOX"])

    def test_mark_read(self):
        service = FakeLabelService({})
        emails = [{"id": "1", "labels": ["INBOX", "UNREAD"]}, {"id": "2", "labels": ["INBOX"]}]
        savegmail.mark_read(service, "me", emails)
        self.assertEqual(service.modified, [{"ids": ["1"], "addLabelIds": [], "removeLabelIds": ["UNREAD"]}])
        self.assertEqual(emails[0]["labels"], ["INBOX"])
        savegmail.mark_read(service, "me", emails)
        self.assertEqual(len(service.modified), 1)  # nothing unread left: no call


class CompactDateTest(unittest.TestCase):
    def test_formats(self):
        from datetime import datetime, timedelta
        now = datetime.now(savegmail.get_localzone())
        ms = lambda moment: int(moment.timestamp() * 1000)
        self.assertRegex(savegmail.compact_date(ms(now)), r"^\d\d:\d\d$")
        self.assertEqual(savegmail.compact_date(ms(now.replace(year=now.year - 1))),
                         now.replace(year=now.year - 1).strftime("%Y-%m-%d %H:%M"))
        if now.timetuple().tm_yday > 1:
            earlier = now - timedelta(days=1)
            self.assertEqual(savegmail.compact_date(ms(earlier)), f"{earlier.day} {earlier.strftime('%b %H:%M')}")


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

    def test_empty_trash_needs_typed_confirmation(self):
        self.assertEqual(pick("Tempty\r"), ("empty_trash", []))
        self.assertEqual(pick("Tdelete\rq"), ("quit", []))

    def test_help_closes_on_any_key(self):
        self.assertEqual(pick("?q\r"), ("download", ["0"]))
        self.assertEqual(pick("?\x1bq"), ("quit", []))

    def test_trash_selection(self):
        self.assertEqual(pick("ady"), ("trash", ["0", "1", "2"]))

    def test_preview_follows_selection(self):
        self.assertEqual(pick("p"), ("preview", ["0"]))
        self.assertEqual(pick(" j p"), ("preview", ["0", "2"]))

    def test_big_preview_needs_confirmation(self):
        many = make_messages(savegmail.PREVIEW_CONFIRM_OVER + 1)
        all_ids = [message["id"] for message in many]
        self.assertEqual(pick("apy", many), ("preview", all_ids))
        self.assertEqual(pick("apnq", many), ("quit", []))
        few = make_messages(savegmail.PREVIEW_CONFIRM_OVER)
        self.assertEqual(pick("ap", few), ("preview", [message["id"] for message in few]))

    def test_hidden_selection_still_applies(self):
        # Selected emails hidden by a filter stay selected (the footer and confirmations say so).
        self.assertEqual(pick("a/Subject 1\rdy"), ("trash", ["0", "1", "2"]))

    def test_undo_only_when_available(self):
        self.assertEqual(pick("uq"), ("quit", []))
        self.assertEqual(pick("u", undo_label="trash (1)"), ("undo", []))

    def test_filter(self):
        self.assertEqual(pick("/Subject 2\r\r"), ("download", ["2"]))

    def test_state_survives_runs(self):
        state = savegmail.new_picker_state()
        self.assertEqual(pick(" jq", state=state), ("quit", []))
        self.assertEqual(state["selected"], {"0"})
        self.assertEqual(pick("s", state=state), ("save", ["0"]))

    def test_load_more_appends_older(self):
        messages = make_messages(2)
        older = [{**make_messages(1)[0], "id": "old", "internalDate": 1}]
        action, ids = pick("m\r", messages, load_more=lambda: (older, False))
        self.assertEqual([message["id"] for message in messages], ["0", "1", "old"])
        self.assertEqual(ids, ["0"])

    def test_star_and_open_keys(self):
        self.assertEqual(pick(" j *"), ("star", ["0", "2"]))
        self.assertEqual(pick(" o"), ("open", ["1"]))  # o: the email under the cursor
        self.assertEqual(pick(" j !"), ("unread", ["0", "2"]))

    def test_archive_and_spam_keys(self):
        self.assertEqual(pick(" j e"), ("archive", ["0", "2"]))
        spam = dict(views=("All mail", "Spam", "Trash"), view=1)
        self.assertEqual(pick("R", **spam), ("not_spam", ["0"]))
        self.assertEqual(pick("eq", **spam), ("quit", []))  # e is off in Spam and Trash
        self.assertEqual(pick("eq", views=("Trash",), view=0), ("quit", []))
        archived = dict(views=("Inbox", "Archived"), view=1)
        self.assertEqual(pick("R", **archived), ("unarchive", ["0"]))
        self.assertEqual(pick("eq", **archived), ("quit", []))

    def test_view_keys(self):
        self.assertEqual(pick("\t"), ("next_view", []))
        self.assertEqual(pick("\x1b[Z"), ("prev_view", []))  # Shift+Tab

    def test_trash_view_keys(self):
        trash = dict(views=("All mail", "Trash"), view=1)
        self.assertEqual(pick("R", **trash), ("restore", ["0"]))
        self.assertEqual(pick("\rdyq", **trash), ("quit", []))  # enter and d are off in Trash
        self.assertEqual(pick("s", **trash), ("save", ["0"]))
        self.assertEqual(pick("Rq"), ("quit", []))  # R only in Trash

    def test_sort_by_size(self):
        messages = make_messages(3)
        for message, size in zip(messages, (10, 30, 20)):
            message["size"] = size
        # Largest first; the cursor follows its email ("0", now last), Home goes back to the top.
        self.assertEqual(pick("z\r", messages), ("download", ["0"]))
        self.assertEqual(pick("z\x1b[H\r", messages), ("download", ["1"]))
        self.assertEqual(pick("z\x1b[Hj\r", messages), ("download", ["2"]))
        state = savegmail.new_picker_state()
        pick("jzq", messages, state=state)  # cursor on "1" (2nd by date), now first by size
        self.assertEqual((state["sort"], state["cursor"]), ("size", 0))

    def test_select_same_sender(self):
        messages = make_messages(4)
        messages[2]["from"] = messages[0]["from"]
        self.assertEqual(pick("A\r", messages), ("download", ["0", "2"]))
        self.assertEqual(pick("AA\r", messages), ("download", ["0"]))  # A again unselects them

    def test_folder_key(self):
        state = savegmail.new_picker_state()
        # f starts from the current folder; backspace / typing edit it; enter applies.
        self.assertEqual(pick("f\x7f2026\r", state=state, folder="~/GMail/"), ("folder", []))
        self.assertEqual(state["folder"], "~/GMail2026")
        self.assertEqual(pick("f\x1bq", folder="~/GMail/"), ("quit", []))  # esc cancels, q then quits
        pick("f\x15~/Archive\r", state=state, folder="~/GMail/")  # ctrl+u clears
        self.assertEqual(state["folder"], "~/Archive")

    def test_refresh_key(self):
        self.assertEqual(pick("r"), ("refresh", []))

    def test_cursor_follows_email_across_runs(self):
        messages = make_messages(3)
        state = savegmail.new_picker_state()
        pick("jq", messages, state=state)
        messages.insert(0, {**messages[0], "id": "new"})
        self.assertEqual(pick("\r", messages, state=state), ("download", ["1"]))


if __name__ == "__main__":
    unittest.main()
