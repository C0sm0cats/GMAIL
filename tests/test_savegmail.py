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


def pick_later(keys, messages, delay=0.5, **kwargs):
    """Like pick, but sends the keys once background work (the sync) had time to run."""
    import threading
    import time
    with create_pipe_input() as pipe:
        with create_app_session(input=pipe, output=DummyOutput()):
            def send():
                for key in keys:
                    time.sleep(delay)
                    pipe.send_text(key)
            threading.Thread(target=send, daemon=True).start()
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

    def test_mark_read_offline_or_signed_out(self):
        # o and p mark the email read: an expired session or no network leaves it unread, without a trace.
        import httplib2
        from unittest import mock
        from google.auth.exceptions import RefreshError
        for error in [RefreshError("invalid_grant"), httplib2.ServerNotFoundError("Unable to find the server")]:
            with self.subTest(error=type(error).__name__):
                emails = [{"id": "1", "labels": ["INBOX", "UNREAD"]}]
                with mock.patch.object(savegmail, "modify_labels", side_effect=error):
                    savegmail.mark_read(object(), "me", emails)
                self.assertEqual(emails[0]["labels"], ["INBOX", "UNREAD"])


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


class RealDateTest(unittest.TestCase):
    def setUp(self):
        from unittest import mock
        from zoneinfo import ZoneInfo
        patcher = mock.patch.object(savegmail, "get_localzone", return_value=ZoneInfo("Europe/Paris"))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_out_of_range_dates_are_invalid(self):
        for header in ("Fri, 31 Dec 9999 23:59:59 -2359", "0001.01.01-00.00.00", "9999.12.31-23.59.59"):
            self.assertEqual(savegmail.get_real_date(header), "Invalid Date", header)

    def test_minus_zero_offset_is_utc(self):
        self.assertEqual(savegmail.get_real_date("Mon, 02 Nov 2026 10:00:00 -0000"), "2026-11-02 11:00:00 CET")
        self.assertEqual(savegmail.get_real_date("Mon, 02 Nov 2026 10:00:00 +0000"), "2026-11-02 11:00:00 CET")

    def test_python39_type_error_is_invalid(self):
        from unittest import mock
        # Python < 3.10 raises TypeError instead of ValueError on an unparseable date.
        with mock.patch.object(savegmail, "parsedate_to_datetime",
                               side_effect=TypeError("cannot unpack non-iterable NoneType object")):
            self.assertEqual(savegmail.get_real_date("2024-02-05 10:00:00"), "Invalid Date")


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
        # Enter once the load is done: leaving the list earlier drops it.
        action, ids = pick_later("m\r", messages, delay=0.2, load_more=lambda: (older, False))
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

    def test_enter_in_trash_says_why(self):
        state = savegmail.new_picker_state()
        self.assertEqual(pick("\rq", views=("All mail", "Trash"), view=1, state=state), ("quit", []))
        self.assertEqual(state["sync_note"][1], "enter is off in Trash · s save, R restore")

    def test_full_header_keeps_selection_sync_and_current_tab(self):
        # 8 tabs with counters, a filter, an expired session and 2 selected emails: from 80 to 140
        # columns the line fits, and keeps the current tab, the filter, the session and the selection.
        badges = {"All mail": ("1,000+", "unread"), "Inbox": ("1,000+", "unread"), "Archived": ("107", "unread"),
                  "Spam": ("25", "unread"), "Trash": ("14", "unread")}
        tail = [("class:dim", " · 1 match "), ("class:accent", "news"),
                ("class:error", " · ↻ Gmail session expired, r to sign in")]
        infos = (" · 8 of ~1,240 emails, 312 unread · newest first", " · 8 of ~1,240 emails, 312 unread",
                 " · 8 of ~1,240 emails")
        for view in (0, 7):
            tabs = [(name, *badges.get(name, (None, "total"))) for name, _ in savegmail.VIEWS]
            current = tabs[view][0]
            for columns in (80, 100, 120, 140):
                line = "".join(text for _, text in savegmail.header_line(tabs, view, infos, tail, "2 selected ", columns))
                self.assertLessEqual(savegmail.cell_len(line), columns - 1, (columns, line))
                for part in (f" {current} ", "1 match news",
                             "↻ Gmail session expired, r to sign in", "2 selected"):
                    self.assertIn(part, line, (columns, line))
                if columns >= 120:
                    self.assertIn(f" {current} ({badges[current][0]}) ", line, (columns, line))
        # With room to spare, nothing is shortened.
        tabs = [(name, *badges.get(name, (None, "total"))) for name, _ in savegmail.VIEWS]
        line = "".join(text for _, text in savegmail.header_line(tabs, 0, infos, [], "", 200))
        self.assertIn(" Inbox (1,000+) ", line)
        self.assertIn("newest first", line)

    def test_colors_readable_on_any_terminal_theme(self):
        # Rendered in the Trash view: no text in ANSI bright black (the background of Solarized dark),
        # and the cursor row, whose background is fixed, also fixes its text color (light themes).
        import io
        import re
        from prompt_toolkit.data_structures import Size
        from prompt_toolkit.output.color_depth import ColorDepth
        from prompt_toolkit.output.vt100 import Vt100_Output
        buffer = io.StringIO()
        output = Vt100_Output(buffer, lambda: Size(24, 120), term="xterm-256color",
                              default_color_depth=ColorDepth.DEPTH_8_BIT)
        with create_pipe_input() as pipe:
            pipe.send_text("q")
            with create_app_session(input=pipe, output=output):
                savegmail.pick_messages(make_messages(3), views=[name for name, _ in savegmail.VIEWS], view=7)
        codes = re.findall(r"\x1b\[([0-9;]*)m", buffer.getvalue())
        self.assertTrue(codes)
        # 90 is bright black text, once 256-color parameters (38;5;N, 48;5;N) are set aside.
        plain = [re.sub(r"[34]8;5;\d+", "", sgr).split(";") for sgr in codes]
        self.assertFalse([sgr for sgr, rest in zip(codes, plain) if "90" in rest], "text in ANSI bright black")
        cursor_row = [sgr for sgr in codes if re.search(r"(^|;)48;5;236(;|$)", sgr)]
        self.assertTrue(cursor_row)
        for sgr in cursor_row:
            self.assertRegex(sgr, r"(^|;)38;5;\d+;48;5;236(;|$)", "cursor row without a text color")

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

    def test_background_sync(self):
        # When the list shows, it syncs on its own: a new email appears, a deleted one goes,
        # labels change, counters fill in, and the cursor stays on the same email.
        messages = make_messages(3)
        badges = {}
        calls = []

        def sync(loaded):
            calls.append([message["id"] for message in loaded])
            new = {**make_messages(1)[0], "id": "new", "internalDate": 1_800_000_000_000}
            return {"new": [new], "gone": {"2"}, "labels": {"0": ["INBOX", "STARRED"]}, "total": None,
                    "badges": {"Inbox": ("4", "unread")}}

        state = savegmail.new_picker_state()
        state["cursor_id"] = "1"
        action, ids = pick_later("\r", messages, sync=sync, badges=badges, state=state)
        self.assertEqual(calls, [["0", "1", "2"]])
        self.assertEqual([message["id"] for message in messages], ["new", "1", "0"])  # newest first
        self.assertEqual(next(m for m in messages if m["id"] == "0")["labels"], ["INBOX", "STARRED"])
        self.assertEqual(badges, {"Inbox": ("4", "unread")})
        self.assertEqual((action, ids), ("download", ["1"]))

    def test_failed_sync_keeps_the_list(self):
        def sync(loaded):
            raise RuntimeError("offline")

        messages = make_messages(2)
        self.assertEqual(pick_later("\r", messages, sync=sync), ("download", ["0"]))
        self.assertEqual(len(messages), 2)

    def test_expired_session_signs_in_again_with_r(self):
        # The sync fails on an expired session: r signs in, then the list syncs again on its own.
        from google.auth.exceptions import RefreshError
        signed_in = []

        def sync(loaded):
            if not signed_in:
                raise RefreshError("invalid_grant")
            return {"new": [], "gone": {"1"}, "labels": {}, "total": None, "badges": {}}

        messages = make_messages(2)
        state = savegmail.new_picker_state()
        action, _ = pick_later("rq", messages, sync=sync, sign_in=lambda: signed_in.append(True), state=state)
        self.assertEqual(signed_in, [True])
        self.assertFalse(state["signed_out"])
        self.assertEqual([message["id"] for message in messages], ["0"])
        self.assertEqual(action, "quit")

    def test_failed_load_more_can_be_retried(self):
        # m while the session expired or Gmail is unreachable: no trace, and m works again afterwards.
        from google.auth.exceptions import RefreshError
        older = [{**make_messages(1)[0], "id": "old", "internalDate": 1}]
        calls = []

        def load_more():
            calls.append(True)
            if len(calls) == 1:
                raise RefreshError("invalid_grant")
            return older, False

        messages = make_messages(2)
        state = savegmail.new_picker_state()
        action, ids = pick_later("mm\r", messages, load_more=load_more, state=state)
        self.assertEqual(len(calls), 2)
        self.assertEqual([message["id"] for message in messages], ["0", "1", "old"])
        self.assertTrue(state["signed_out"])
        self.assertFalse(state["loading"])
        self.assertEqual((action, ids), ("download", ["0"]))

    def test_leaving_the_list_does_not_wait_for_background_work(self):
        # Tab, q or an action during a sync, an m or an r: the list goes at once, the work is dropped.
        import threading
        import time
        from google.auth.exceptions import RefreshError
        release = threading.Event()
        self.addCleanup(release.set)
        applied = []

        def slow_sync(loaded):
            release.wait(10)
            return {"new": [], "gone": {"0"}, "labels": {}, "total": None, "badges": {}}

        def slow_load_more():
            release.wait(10)
            return [{**make_messages(1)[0], "id": "old", "internalDate": 1}], False, lambda: applied.append(True)

        def expired(loaded):
            raise RefreshError("invalid_grant")

        cases = [("\t", {"sync": slow_sync}, "next_view"), ("q", {"sync": slow_sync}, "quit"),
                 ("m\t", {"load_more": slow_load_more}, "next_view"),
                 ("rq", {"sync": expired, "sign_in": lambda: release.wait(10)}, "quit")]
        for keys, kwargs, expected in cases:
            with self.subTest(keys=keys):
                messages = make_messages(2)
                start = time.monotonic()
                action, _ = pick_later(keys, messages, delay=0.3, **kwargs)
                self.assertEqual(action, expected)
                self.assertLess(time.monotonic() - start, 0.3 * len(keys) + 1.5)
                self.assertEqual([message["id"] for message in messages], ["0", "1"])  # result dropped
        self.assertEqual(applied, [])

    def test_r_does_nothing_while_signed_in(self):
        signed_in = []
        action, _ = pick_later("rq", make_messages(2), sign_in=lambda: signed_in.append(True))
        self.assertEqual((signed_in, action), ([], "quit"))

    def test_cursor_follows_email_across_runs(self):
        messages = make_messages(3)
        state = savegmail.new_picker_state()
        pick("jq", messages, state=state)
        messages.insert(0, {**messages[0], "id": "new"})
        self.assertEqual(pick("\r", messages, state=state), ("download", ["1"]))


class FakeRawService:
    def __init__(self, raw):
        self.raw = raw

    def users(self):
        return self

    def messages(self):
        return self

    def get(self, **kwargs):
        return self

    def execute(self):
        return {"raw": self.raw}


class FakePdfPage:
    def __init__(self, fail):
        self.fail = fail

    def set_content(self, *args, **kwargs):
        pass

    def evaluate(self, *args, **kwargs):
        return True

    def route(self, *args):
        pass

    def wait_for_timeout(self, *args):
        pass

    def pdf(self, path, **kwargs):
        if self.fail:
            raise ValueError("render failed")
        with open(path, "wb") as f:
            f.write(b"%PDF-RENDERED")

    def close(self):
        pass


class FakePdfBrowser:
    def __init__(self, fail=False):
        self.fail = fail

    def new_page(self, **kwargs):
        return FakePdfPage(self.fail)


class FakeRoute:
    def __init__(self, request):
        self.request = request
        self.result = None

    def fulfill(self, status):
        self.result = ("fulfill", status)

    def continue_(self):
        self.result = ("continue",)


class FakeNavRequest:
    def __init__(self, navigation, frame, url="https://example.com/x"):
        self.navigation, self.frame, self.url = navigation, frame, url

    def is_navigation_request(self):
        return self.navigation


class RecordingPage(FakePdfPage):
    def __init__(self):
        super().__init__(False)
        self.main_frame = object()
        self.routes = []

    def route(self, pattern, handler):
        self.routes.append(handler)

    def emulate_media(self, **kwargs):
        pass


class RecordingBrowser:
    def __init__(self):
        self.pages = []

    def new_page(self, **kwargs):
        page = RecordingPage()
        page.kwargs = kwargs
        self.pages.append(page)
        return page


class SenderContentPageTest(unittest.TestCase):
    """Email pages run no sender script and never navigate away from the email."""

    def test_email_pages_disable_scripts_and_block_navigation(self):
        import base64
        import tempfile
        from email.message import EmailMessage
        msg = EmailMessage()
        msg["Subject"] = "Hello <img src=x onerror=alert(1)>"
        msg["From"] = "s@example.com"
        msg.set_content("alt")
        msg.add_alternative('<meta http-equiv="refresh" content="0;url=http://127.0.0.1:9/"><p>Body</p>'
                            '<script>for(;;){}</script>', subtype="html")
        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
        browser = RecordingBrowser()
        with tempfile.TemporaryDirectory() as save_dir:
            savegmail.save_email_and_attachments(FakeRawService(raw), "me", "id1", save_dir, browser)
        # The email page and the header/footer measurement page.
        self.assertEqual(len(browser.pages), 2)
        for page in browser.pages:
            self.assertEqual(page.kwargs.get("java_script_enabled"), False)
            self.assertEqual(len(page.routes), 1)
            handler = page.routes[0]
            outcomes = {}
            for name, request in {
                "main navigation": FakeNavRequest(True, page.main_frame),
                "iframe navigation": FakeNavRequest(True, object()),
                "image": FakeNavRequest(False, page.main_frame),
            }.items():
                route = FakeRoute(request)
                handler(route)
                outcomes[name] = route.result
            self.assertEqual(outcomes, {"main navigation": ("fulfill", 204),
                                        "iframe navigation": ("continue",), "image": ("continue",)})


def png_image(width, height):
    """A valid opaque PNG of the given size."""
    import struct
    import zlib

    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    rows = b"".join(b"\x00" + b"\xff\x00\x00" * width for _ in range(height))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b""))


def inline_image_email(body_html, image):
    """Raw (base64url) multipart/related email whose HTML body may reference the image as cid:logo123."""
    import base64
    from email.message import EmailMessage
    msg = EmailMessage()
    msg["Subject"] = "Inline image"
    msg["From"] = "s@example.com"
    msg.set_content("alt")
    msg.add_alternative(body_html, subtype="html")
    msg.get_payload()[1].add_related(image, "image", "png", cid="<logo123>")
    return base64.urlsafe_b64encode(msg.as_bytes()).decode()


class FulfillRoute:
    def __init__(self, request):
        self.request = request
        self.result = None

    def fulfill(self, **kwargs):
        self.result = ("fulfill", kwargs)

    def continue_(self):
        self.result = ("continue",)


class ContentRecordingPage(RecordingPage):
    def set_content(self, html, **kwargs):
        self.html = html

    def evaluate(self, script, *args, **kwargs):
        self.scripts = getattr(self, "scripts", []) + [script]
        return True


class ContentRecordingBrowser(RecordingBrowser):
    def new_page(self, **kwargs):
        page = ContentRecordingPage()
        self.pages.append(page)
        return page


class InlineImageTest(unittest.TestCase):
    """Inline (cid:) and deferred (data-src) images of an email end up in its PDF."""

    def test_cid_image_is_served_once_instead_of_copied_per_reference(self):
        import tempfile
        image = png_image(40, 20) + b"\x00" * 50_000  # trailing bytes: a large image, still a valid PNG
        raw = inline_image_email("<p>Logo</p>" + '<img src="cid:logo123">' * 200, image)
        browser = ContentRecordingBrowser()
        with tempfile.TemporaryDirectory() as save_dir:
            savegmail.save_email_and_attachments(FakeRawService(raw), "me", "id1", save_dir, browser)
        page = browser.pages[0]  # the email page; the second one measures the header and footer
        url = savegmail.INLINE_IMAGE_URL.format(0)
        self.assertNotIn("cid:", page.html)
        self.assertEqual(page.html.count(f'src="{url}"'), 200)
        # The HTML does not grow with each reference to the image (it used to embed it 200 times).
        self.assertLess(len(page.html), len(image))
        route = FulfillRoute(FakeNavRequest(False, page.main_frame, url))
        page.routes[0](route)
        self.assertEqual(route.result, ("fulfill", {"status": 200, "content_type": "image/png", "body": image}))
        # Deferred images are given their real source before printing.
        self.assertTrue(any("img.src = img.dataset.src" in script for script in page.scripts))

    def test_images_are_loaded_in_chromium_before_printing(self):
        import base64
        import tempfile
        from playwright.sync_api import sync_playwright
        image = png_image(40, 20)
        data_url = "data:image/png;base64," + base64.b64encode(image).decode()
        raw = inline_image_email(f'<img id="cid" src="cid:logo123"><img id="lazy" data-src="{data_url}">', image)
        widths = []

        class SpyBrowser:
            """Real Chromium; notes the width of each image of the email page when it is printed."""
            def __init__(self, browser):
                self.browser = browser

            def new_page(self, **kwargs):
                page = self.browser.new_page(**kwargs)
                pdf = page.pdf

                def spy_pdf(**pdf_kwargs):
                    widths.append(page.evaluate("[...document.images].map(img => [img.id, img.naturalWidth])"))
                    return pdf(**pdf_kwargs)

                page.pdf = spy_pdf
                return page

        with sync_playwright() as playwright:
            try:
                browser = playwright.chromium.launch(channel="chromium")
            except Exception as error:  # no Playwright Chromium here; never install it from a test
                self.skipTest(f"Chromium unavailable: {error}")
            try:
                with tempfile.TemporaryDirectory() as save_dir:
                    savegmail.save_email_and_attachments(FakeRawService(raw), "me", "id1", save_dir,
                                                         SpyBrowser(browser))
                    self.assertTrue(browser.is_connected())
            finally:
                browser.close()
        self.assertEqual(widths, [[["cid", 40], ["lazy", 40]]])


class HugeHeaderTest(unittest.TestCase):
    """Python parses headers in quadratic time and memory: a sender's huge header is cut before parsing."""

    def test_encoded_word_headers_are_cut_before_parsing(self):
        import base64
        import tempfile
        words = " ".join(["=?utf-8?q?ab?="] * 5000)  # 75 KB; a few hundred KB took several GB
        raw = (f"Subject: {words}\r\nFrom: {words}\r\nMIME-Version: 1.0\r\n"
               "Content-Type: text/html; charset=utf-8\r\n\r\n<p>Body</p>\r\n").encode()
        headers = []

        class HeaderRecordingPage(ContentRecordingPage):
            def pdf(self, path, **kwargs):
                headers.append(kwargs["header_template"])
                super().pdf(path, **kwargs)

        class HeaderRecordingBrowser(ContentRecordingBrowser):
            def new_page(self, **kwargs):
                page = HeaderRecordingPage()
                self.pages.append(page)
                return page

        with tempfile.TemporaryDirectory() as save_dir:
            savegmail.save_email_and_attachments(
                FakeRawService(base64.urlsafe_b64encode(raw).decode()), "me", "id1", save_dir,
                HeaderRecordingBrowser())
        self.assertIn("ab" * 1000, headers[0])  # the start of the subject and sender is still shown
        self.assertNotIn("ab" * 5000, headers[0])  # but not all 75 KB of them


class PageCountTest(unittest.TestCase):
    """A sender's forced page breaks used to make Chromium print 20,000 pages, for minutes per email."""

    @staticmethod
    def page_break_email(breaks):
        import base64
        body = "<p>Hi</p><style>i{display:block;break-after:page}</style>" + "<i></i>" * breaks
        raw = ("Subject: Breaks\r\nFrom: s@example.com\r\nMIME-Version: 1.0\r\n"
               "Content-Type: text/html; charset=utf-8\r\n\r\n" + body + "\r\n").encode()
        return base64.urlsafe_b64encode(raw).decode()

    def test_printed_pages_are_capped(self):
        import tempfile
        options = []

        class OptionsRecordingPage(ContentRecordingPage):
            def pdf(self, path, **kwargs):
                options.append(kwargs)
                super().pdf(path, **kwargs)

        class OptionsRecordingBrowser(ContentRecordingBrowser):
            def new_page(self, **kwargs):
                page = OptionsRecordingPage()
                self.pages.append(page)
                return page

        with tempfile.TemporaryDirectory() as save_dir:
            savegmail.save_email_and_attachments(FakeRawService(self.page_break_email(10)), "me", "id1",
                                                 save_dir, OptionsRecordingBrowser())
        self.assertEqual(options[0].get("page_ranges"), f"1-{savegmail.MAX_PDF_PAGES}")

    def test_chromium_prints_at_most_max_pages(self):
        import re
        import tempfile
        from unittest import mock
        from playwright.sync_api import sync_playwright
        with sync_playwright() as playwright:
            try:
                browser = playwright.chromium.launch(channel="chromium")
            except Exception as error:  # no Playwright Chromium here; never install it from a test
                self.skipTest(f"Chromium unavailable: {error}")
            try:
                with tempfile.TemporaryDirectory() as save_dir, mock.patch.object(savegmail, "MAX_PDF_PAGES", 5):
                    result = savegmail.save_email_and_attachments(
                        FakeRawService(self.page_break_email(50)), "me", "id1", save_dir, browser)
                    with open(os.path.join(save_dir, result["pdf"]), "rb") as f:
                        pdf = f.read()
            finally:
                browser.close()
        self.assertEqual(len(re.findall(rb"/Type\s*/Page[^s]", pdf)), 5)


class PdfFileNameTest(unittest.TestCase):
    """The rendered PDF never overwrites or deletes a file the program did not create."""

    def save(self, save_dir, subject, attachment=None, fail=False):
        import base64
        from email.message import EmailMessage
        from unittest import mock
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = "Sender <s@example.com>"
        msg.set_content("hello")
        if attachment:
            msg.add_attachment(attachment[1], maintype="application", subtype="pdf", filename=attachment[0])
        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
        with mock.patch.object(savegmail, "measure_pdf_margins", return_value={}):
            return savegmail.save_email_and_attachments(
                FakeRawService(raw), "me", "id1", save_dir, FakePdfBrowser(fail))

    def read(self, path):
        with open(path, "rb") as f:
            return f.read()

    def test_pdf_keeps_existing_files(self):
        import tempfile
        with tempfile.TemporaryDirectory() as save_dir:
            # Attachment named like the subject: both files must survive.
            result = self.save(save_dir, "Invoice", attachment=("Invoice.pdf", b"%PDF-ATTACHMENT"))
            self.assertEqual(self.read(os.path.join(save_dir, "Invoice.pdf")), b"%PDF-ATTACHMENT")
            self.assertEqual(self.read(os.path.join(save_dir, result["pdf"])), b"%PDF-RENDERED")

            # A file already in the folder survives a successful save...
            with open(os.path.join(save_dir, "Contract.pdf"), "wb") as f:
                f.write(b"USER-CONTRACT")
            self.save(save_dir, "Contract")
            self.assertEqual(self.read(os.path.join(save_dir, "Contract.pdf")), b"USER-CONTRACT")

            # ...and a failed one, which removes only what it wrote.
            with open(os.path.join(save_dir, "Report.pdf"), "wb") as f:
                f.write(b"USER-REPORT")
            with self.assertRaises(RuntimeError):
                self.save(save_dir, "Report", fail=True)
            self.assertEqual(self.read(os.path.join(save_dir, "Report.pdf")), b"USER-REPORT")
            self.assertFalse([name for name in os.listdir(save_dir) if name.startswith(".")])

    def test_slashes_in_names_stay_in_save_dir(self):
        import tempfile
        with tempfile.TemporaryDirectory() as outer:
            save_dir = os.path.join(outer, "a", "b")
            os.makedirs(save_dir)
            absolute = os.path.join(outer, "absolute-escape.pdf")
            results = [
                self.save(save_dir, "Hello", attachment=("../../attach-escape.pdf", b"A")),
                self.save(save_dir, "Hello", attachment=(absolute, b"B")),
                self.save(save_dir, "../../subject-escape"),
            ]
            root = os.path.realpath(save_dir)
            for result in results:
                for path in result["files"]:
                    self.assertEqual(os.path.dirname(os.path.realpath(path)), root, path)
            found = [os.path.relpath(os.path.join(d, f), outer) for d, _, files in os.walk(outer) for f in files]
            self.assertTrue(all(path.startswith(os.path.join("a", "b") + os.sep) for path in found), found)
            self.assertEqual(len(found), 5)  # 3 PDFs + 2 attachments

    def test_same_attachment_name_gets_suffix(self):
        import tempfile
        with tempfile.TemporaryDirectory() as save_dir:
            # Two emails saved one after the other, each with its own invoice.pdf.
            self.save(save_dir, "March", attachment=("invoice.pdf", b"march"))
            self.save(save_dir, "April", attachment=("invoice.pdf", b"april"))
            attachments = {name: self.read(os.path.join(save_dir, name))
                           for name in os.listdir(save_dir) if name.startswith("invoice")}
            self.assertEqual(attachments, {"invoice.pdf": b"march", "invoice(1).pdf": b"april"})


class FakeSaveService(FakeService):
    """Serves one raw email and records the ids moved to the trash (when the batch runs)."""

    def __init__(self, raw):
        super().__init__()
        self.raw, self.trashed = raw, []

    def users(self):
        return self

    def messages(self):
        return self

    def get(self, **kwargs):
        return FakeRawService(self.raw)

    def trash(self, userId, id):
        service = self

        class Request:
            def execute(self):
                service.trashed.append(id)
                return {"id": id}
        return Request()


class SaveMessagesAttachmentTest(unittest.TestCase):
    def test_enter_writes_attachment_before_trashing(self):
        import base64
        import io
        import tempfile
        from email.message import EmailMessage
        from unittest import mock
        content = b"%PDF-1.4 contract\x00\xff"
        msg = EmailMessage()
        msg["Subject"] = "Invoice"
        msg["From"] = "Sender <s@example.com>"
        msg.set_content("hello")
        msg.add_attachment(content, maintype="application", subtype="pdf", filename="contract.pdf")
        service = FakeSaveService(base64.urlsafe_b64encode(msg.as_bytes()).decode())
        message = {"id": "m1", "from": "Sender <s@example.com>", "subject": "Invoice",
                   "snippet": "", "internalDate": 1_700_000_000_000}
        with tempfile.TemporaryDirectory() as save_dir, \
                mock.patch.object(savegmail, "measure_pdf_margins", return_value={}), \
                mock.patch.object(savegmail, "console", savegmail.Console(file=io.StringIO())):
            saved, count, failed, files = savegmail.save_messages(
                service, "me", [message], save_dir, FakePdfBrowser(), True)
            path = os.path.join(save_dir, "contract.pdf")
            with open(path, "rb") as f:
                self.assertEqual(f.read(), content)
            self.assertIn(path, files["m1"])
        self.assertEqual([m["id"] for m in saved], ["m1"])
        self.assertEqual((count, failed), (1, {}))
        self.assertEqual(service.trashed, ["m1"])


class FakeGmail:
    """Where each email is in a fake Gmail: inbox, archive, trash or gone (permanently deleted)."""

    def __init__(self, places, save_dir, failing_untrash=(), failing=()):
        self.places, self.save_dir, self.failing_untrash = dict(places), save_dir, set(failing_untrash)
        self.failing = set(failing)  # emails whose save or move to trash fails

    def message(self, msg_id):
        return {"id": msg_id, "from": f"S <{msg_id}@example.com>", "subject": f"Subject {msg_id}",
                "snippet": "", "internalDate": 1_700_000_000_000, "labels": []}

    def list_candidate_messages(self, service, user_id, query="", max_results=50, page_token=None, in_trash=False):
        wanted = {"trash"} if in_trash else {"inbox", "archive"}
        return [self.message(msg_id) for msg_id, place in self.places.items() if place in wanted], None

    def save_messages(self, service, user_id, messages, save_dir, browser, trash_after):
        files = {}
        failed = {message["id"]: "PDF generation failed: timeout" for message in messages if message["id"] in self.failing}
        messages = [message for message in messages if message["id"] not in self.failing]
        for message in messages:
            paths = [os.path.join(save_dir, f"{message['id']}.pdf"), os.path.join(save_dir, f"{message['id']}-att.bin")]
            for path in paths:
                with open(path, "w") as f:
                    f.write("saved")
            files[message["id"]] = paths
            if trash_after:
                self.places[message["id"]] = "trash"
        return list(messages), len(messages), failed, files

    def trash_messages(self, service, user_id, ids):
        for msg_id in ids:
            if msg_id not in self.failing:
                self.places[msg_id] = "trash"
        return {msg_id: RuntimeError("Backend Error") for msg_id in ids if msg_id in self.failing}

    def untrash_messages(self, service, user_id, ids):
        errors = {}
        for msg_id in ids:
            if msg_id in self.failing_untrash or self.places[msg_id] != "trash":
                errors[msg_id] = RuntimeError("404 Requested entity was not found.")
            else:
                self.places[msg_id] = "inbox"
        return errors

    def modify_labels(self, service, user_id, ids, add=(), remove=()):
        for msg_id in ids:
            if self.places[msg_id] == "gone":
                raise RuntimeError("404 Requested entity was not found.")
            if "INBOX" in add:
                self.places[msg_id] = "inbox"
            if "INBOX" in remove:
                self.places[msg_id] = "archive"

    def list_trash_ids(self, service, user_id):
        return [msg_id for msg_id, place in self.places.items() if place == "trash"]

    def delete_messages(self, service, user_id, ids):
        for msg_id in ids:
            self.places[msg_id] = "gone"


class FakeUsers:
    def getProfile(self, userId):
        return FakeResult({"emailAddress": "me@example.com"})


class FakeSessionService:
    def users(self):
        return FakeUsers()


class FakePlaywright:
    def start(self):
        return self

    def stop(self):
        pass


class FakeBatchApi:
    """Gmail API whose batchDelete / batchModify move emails in a FakeGmail; the fail_on-th call fails."""

    real_calls = {"modify_labels", "delete_messages"}  # savegmail functions run_session leaves real

    def __init__(self, fail_on=None):
        self.gmail, self.fail_on, self.calls = None, fail_on, []

    def users(self):
        return self

    def messages(self):
        return self

    def getProfile(self, userId):
        return FakeResult({"emailAddress": "me@example.com"})

    def batchDelete(self, userId, body):
        return self.request("batchDelete", body["ids"], lambda msg_id: "gone")

    def batchModify(self, userId, body):
        def place(msg_id):
            if "INBOX" in body["addLabelIds"]:
                return "inbox"
            return "archive" if "INBOX" in body["removeLabelIds"] else self.gmail.places[msg_id]
        return self.request("batchModify", body["ids"], place)

    def request(self, name, ids, place):
        from unittest import mock
        self.calls.append((name, len(ids)))
        failing = len(self.calls) == self.fail_on

        def execute():
            if failing:
                raise savegmail.HttpError(mock.Mock(status=503, reason="Backend Error"), b"Backend Error")
            if self.gmail is not None:
                for msg_id in ids:
                    self.gmail.places[msg_id] = place(msg_id)
            return {}
        return mock.Mock(execute=execute)


class FakeMailboxApi(FakeBatchApi):
    """FakeBatchApi that also lists emails like Gmail's messages.list: trash only when labelIds asks for it."""

    real_calls = FakeBatchApi.real_calls | {"list_trash_ids"}

    def list(self, userId, labelIds=None, maxResults=100, pageToken=None, **kwargs):
        wanted = {"trash"} if labelIds and "TRASH" in labelIds else {"inbox", "archive"}
        return FakeResult({"messages": [{"id": msg_id} for msg_id, place in self.gmail.places.items()
                                        if place in wanted]})

    def list_next(self, request, results):
        return None


class GmailCallSizeTest(unittest.TestCase):
    """Gmail takes at most 1000 ids per batchDelete / batchModify."""

    def test_delete_messages_splits_by_1000(self):
        api = FakeBatchApi()
        savegmail.delete_messages(api, "me", [str(i) for i in range(1500)])
        self.assertEqual(api.calls, [("batchDelete", 1000), ("batchDelete", 500)])

    def test_modify_labels_splits_by_1000(self):
        api = FakeBatchApi()
        savegmail.modify_labels(api, "me", [str(i) for i in range(2000)], add=["STARRED"])
        self.assertEqual(api.calls, [("batchModify", 1000), ("batchModify", 1000)])

    def test_failed_later_call_reports_what_was_done(self):
        for call, name in [(savegmail.delete_messages, "batchDelete"), (savegmail.modify_labels, "batchModify")]:
            with self.subTest(name=name):
                ids = [str(i) for i in range(1500)]
                with self.assertRaises(savegmail.PartialBatchError) as caught:
                    call(FakeBatchApi(fail_on=2), "me", ids)
                self.assertEqual(caught.exception.done, ids[:1000])
                self.assertIsInstance(caught.exception.error, savegmail.HttpError)
                # A first call that fails: nothing was done, the Gmail error as is.
                with self.assertRaises(savegmail.HttpError):
                    call(FakeBatchApi(fail_on=1), "me", ids)


class UndoAfterDeleteTest(unittest.TestCase):
    """Drives interactive_download_main with a fake Gmail and scripted keys, like s, D, u."""

    def run_session(self, places, steps, failing_untrash=(), failing=(), api=None, down=None):
        """steps: (action, ids); an undo is only pressed when u is offered, as in the list.

        api: a fake Gmail API (FakeBatchApi) that the real modify_labels and delete_messages call.
        down: (n, exception): once n steps are done, every Gmail call raises it (session expired, offline);
        self.signed_out holds whether the list offered r to sign in again, before each step.
        Returns (fake Gmail, files left in the download folder, undo label offered before each step);
        self.notices holds the notice shown before each step, as plain text lines.
        """
        import io
        import tempfile
        from unittest import mock
        from rich.console import Console
        save_dir = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, save_dir, True)
        gmail = FakeGmail(places, save_dir, failing_untrash, failing)
        if api is not None:
            api.gmail = gmail
        steps, offered, self.notices, self.signed_out = list(steps), [], [], []
        broken = []

        def ask(messages, load_more, state, notice, undo_label, *rest):
            if down is not None and len(offered) == down[0]:
                broken.append(down[1])
            offered.append(undo_label)
            self.signed_out.append(state["signed_out"])
            self.notices.append(["".join(text for _, text in line) for line in notice])
            if not steps:
                return "quit", []
            action, ids = steps.pop(0)
            if action == "undo" and undo_label is None:
                return ask(messages, load_more, state, notice, undo_label, *rest)
            return action, [gmail.message(msg_id) for msg_id in ids]

        fakes = {name: getattr(gmail, name) for name in [
            "list_candidate_messages", "save_messages", "trash_messages", "untrash_messages",
            "modify_labels", "list_trash_ids", "delete_messages"]
            if api is None or name not in api.real_calls}

        def failing_when_down(call):
            def wrapper(*args, **kwargs):
                if broken:
                    raise broken[0]
                return call(*args, **kwargs)
            return wrapper
        fakes = {name: failing_when_down(call) for name, call in fakes.items()}
        with mock.patch.multiple(
            savegmail, authenticate=lambda: object(), build=lambda *a, **k: api or FakeSessionService(),
            user_labels=lambda *a: {}, ask_user_to_select_messages=ask,
            refresh_messages=lambda *a, **k: ([], set()), refresh_labels=lambda *a: 0,
            sync_playwright=lambda: FakePlaywright(), launch_browser=lambda *a, **k: mock.Mock(),
            open_quietly=lambda url: True, console=Console(file=io.StringIO()), **fakes,
        ), mock.patch.object(sys, "argv", ["savegmail", "--download-path", save_dir]):
            savegmail.interactive_download_main()
        return gmail, sorted(os.listdir(save_dir)), offered

    def test_save_keep_then_delete_keeps_the_only_copy(self):
        gmail, left, offered = self.run_session({"A": "inbox"}, [("save", ["A"]), ("delete", ["A"]), ("undo", [])])
        self.assertEqual(left, ["A-att.bin", "A.pdf"])
        self.assertIsNone(offered[-1])

    def test_save_keep_in_trash_then_empty_trash_keeps_the_only_copy(self):
        gmail, left, offered = self.run_session({"A": "trash"}, [("save", ["A"]), ("empty_trash", []), ("undo", [])])
        self.assertEqual(gmail.places["A"], "gone")
        self.assertEqual(left, ["A-att.bin", "A.pdf"])
        self.assertIsNone(offered[-1])

    def test_failed_untrash_keeps_files(self):
        gmail, left, offered = self.run_session({"A": "inbox"}, [("download", ["A"]), ("undo", [])],
                                                failing_untrash={"A"})
        self.assertEqual(gmail.places["A"], "trash")
        self.assertEqual(left, ["A-att.bin", "A.pdf"])
        self.assertEqual(offered[-1], "save+trash (1)")

    def test_undo_save_trash(self):
        gmail, left, offered = self.run_session({"A": "inbox"}, [("download", ["A"]), ("undo", [])])
        self.assertEqual(gmail.places["A"], "inbox")
        self.assertEqual(left, [])
        self.assertIsNone(offered[-1])

    def test_no_undo_of_permanently_deleted_emails(self):
        for first in ["trash", "download"]:
            with self.subTest(first=first):
                gmail, left, offered = self.run_session({"A": "inbox"}, [(first, ["A"]), ("delete", ["A"])])
                self.assertIsNone(offered[-1])

    def test_archive_undo_survives_delete_and_empty_trash(self):
        gmail, left, offered = self.run_session({"A": "inbox", "X": "trash"},
                                                [("archive", ["A"]), ("empty_trash", []), ("undo", [])])
        self.assertEqual(offered[-2], "archive (1)")
        self.assertEqual(gmail.places, {"A": "inbox", "X": "gone"})
        gmail, left, offered = self.run_session({"A": "inbox", "B": "inbox"},
                                                [("archive", ["A", "B"]), ("delete", ["B"]), ("undo", [])])
        self.assertEqual(offered[-2], "archive (1)")
        self.assertEqual(gmail.places, {"A": "inbox", "B": "gone"})

    def test_partial_delete_keeps_the_deleted_emails_files(self):
        ids = [f"m{i}" for i in range(1500)]
        api = FakeBatchApi(fail_on=2)
        gmail, left, offered = self.run_session({msg_id: "inbox" for msg_id in ids},
                                                [("save", ids), ("delete", ids), ("undo", [])], api=api)
        self.assertEqual(api.calls, [("batchDelete", 1000), ("batchDelete", 500)])
        self.assertEqual(self.notices[2][0], " ✓ 1000 emails permanently deleted")
        self.assertTrue(self.notices[2][1].startswith(" ✗ Could not delete 500 emails"))
        self.assertEqual(offered[2], "save+keep (500)")
        # u removes only the files of the 500 emails still in Gmail; the others are the only copy.
        self.assertEqual(len(left), 2000)
        gone = {msg_id for msg_id, place in gmail.places.items() if place == "gone"}
        self.assertEqual(len(gone), 1000)
        self.assertEqual({name.split(".")[0].split("-")[0] for name in left}, gone)

    def test_partial_empty_trash_counts_the_deleted_emails(self):
        ids = [f"m{i}" for i in range(1500)]
        gmail, left, offered = self.run_session({msg_id: "trash" for msg_id in ids}, [("empty_trash", [])],
                                                api=FakeBatchApi(fail_on=2))
        self.assertEqual(self.notices[1][0], " ✓ 1000 emails permanently deleted")
        self.assertTrue(self.notices[1][1].startswith(" ✗ Could not empty the trash"))
        self.assertEqual(sum(place == "gone" for place in gmail.places.values()), 1000)

    def test_partial_archive_can_be_undone(self):
        ids = [f"m{i}" for i in range(1500)]
        gmail, left, offered = self.run_session({msg_id: "inbox" for msg_id in ids}, [("archive", ids), ("undo", [])],
                                                api=FakeBatchApi(fail_on=2))
        self.assertEqual(self.notices[1][0], " ✓ 1000 emails archived · u undo")
        self.assertTrue(self.notices[1][1].startswith(" ✗ Could not archive 500 emails"))
        self.assertEqual(offered[1], "archive (1000)")
        self.assertEqual(set(gmail.places.values()), {"inbox"})

    def test_partial_star_and_read_state(self):
        ids = [f"m{i}" for i in range(1500)]
        for action, done, failed in [("star", " ★ 1000 emails starred", " ✗ Could not change the star of 500 emails"),
                                     ("unread", " ● 1000 emails marked as unread",
                                      " ✗ Could not change the read state of 500 emails")]:
            with self.subTest(action=action):
                self.run_session({msg_id: "inbox" for msg_id in ids}, [(action, ids)], api=FakeBatchApi(fail_on=2))
                self.assertEqual(self.notices[1][0], done)
                self.assertTrue(self.notices[1][1].startswith(failed))

    def test_nothing_done_shows_no_success(self):
        cases = [("download", "inbox", {}, " ✗ Nothing saved"), ("save", "inbox", {}, " ✗ Nothing saved"),
                 ("trash", "inbox", {}, " ✗ Nothing moved to trash"),
                 ("restore", "trash", {"failing_untrash": {"A"}}, " ✗ Nothing restored from trash")]
        for action, place, failures, first in cases:
            with self.subTest(action=action):
                failures = failures or {"failing": {"A"}}
                gmail, left, offered = self.run_session({"A": place}, [(action, ["A"])], **failures)
                self.assertEqual(self.notices[1][0], first)
                self.assertTrue(self.notices[1][1].startswith(" ✗ Subject A"))
                self.assertEqual(gmail.places["A"], place)
                self.assertIsNone(offered[1])


    def test_expired_session_or_offline_keeps_the_list(self):
        # The session expires, or the network drops, after a d: no key closes the list, the undo stays.
        import httplib2
        from unittest import mock
        from google.auth.exceptions import RefreshError
        failures = [(RefreshError("invalid_grant: Token has been expired or revoked."), " ✗ Gmail session expired"),
                    (httplib2.ServerNotFoundError("Unable to find the server"), " ✗ Gmail request failed"),
                    (savegmail.HttpError(mock.Mock(status=503, reason="Backend Error"), b"Backend Error"),
                     " ✗ Gmail request failed")]
        actions = [("star", ["B"]), ("unread", ["B"]), ("archive", ["B"]), ("open", ["B"]), ("undo", []),
                   ("next_view", []), ("prev_view", []), ("trash", ["B"]), ("restore", ["A"])]
        for error, shown in failures:
            for action, ids in actions:
                with self.subTest(error=type(error).__name__, action=action):
                    gmail, left, offered = self.run_session(
                        {"A": "inbox", "B": "inbox"}, [("trash", ["A"]), (action, ids), ("undo", [])],
                        down=(1, error))
                    self.assertEqual(offered[1:], ["trash (1)"] * 3)
                    if action == "open":  # o opens Gmail in the browser; failing to mark it read says nothing
                        continue
                    # e, ! and * say which emails they could not change; the others that nothing was done.
                    self.assertTrue(self.notices[2][0].startswith(
                        " ✗ Could not" if action in {"star", "unread", "archive"} else shown), self.notices[2])
                    self.assertEqual(self.signed_out[2], isinstance(error, RefreshError))
                    self.assertEqual(gmail.places, {"A": "trash", "B": "inbox"})


class EmptyTrashCommandTest(unittest.TestCase):
    def test_partial_failure_reports_deleted_emails(self):
        import io
        from unittest import mock
        from rich.console import Console
        ids = [str(i) for i in range(1500)]
        output = io.StringIO()
        test_console = Console(file=output, width=200)
        test_console.input = lambda prompt: "y"
        with mock.patch.multiple(savegmail, console=test_console, list_trash_ids=lambda *a: ids):
            savegmail.empty_trash(FakeBatchApi(fail_on=2))
        self.assertIn("1000 message(s) permanently deleted from trash, then: ", output.getvalue())
        self.assertIn("Backend Error", output.getvalue())

    def run_empty_trash(self, answer):
        import io
        from unittest import mock
        from rich.console import Console
        api = FakeBatchApi()
        output = io.StringIO()
        test_console = Console(file=output, width=200)
        test_console.input = lambda prompt: answer
        with mock.patch.multiple(savegmail, console=test_console, list_trash_ids=lambda *a: ["1", "2"]):
            savegmail.empty_trash(api)
        return api.calls, output.getvalue()

    def test_declined_confirmation_deletes_nothing(self):
        for answer in ("n", "", "no", "maybe"):
            with self.subTest(answer=answer):
                calls, output = self.run_empty_trash(answer)
                self.assertEqual(calls, [])
                self.assertIn("Cancelled.", output)

    def test_accepted_confirmation_deletes_trash(self):
        for answer in ("y", "yes", " Y "):
            with self.subTest(answer=answer):
                calls, output = self.run_empty_trash(answer)
                self.assertEqual(calls, [("batchDelete", 2)])
                self.assertIn("2 message(s) permanently deleted from trash.", output)


class ActionTargetsTest(unittest.TestCase):
    """D, d, T and --trash act on the chosen emails or the trash only, never on the rest of the view or mailbox."""

    run_session = UndoAfterDeleteTest.run_session

    def test_delete_removes_only_the_chosen_email(self):
        gmail, left, offered = self.run_session({"m0": "inbox", "m1": "inbox", "m2": "inbox"}, [("delete", ["m1"])],
                                                api=FakeMailboxApi())
        self.assertEqual(gmail.places, {"m0": "inbox", "m1": "gone", "m2": "inbox"})
        self.assertEqual(self.notices[1][0], " ✓ 1 email permanently deleted")

    def test_trash_moves_only_the_chosen_email(self):
        gmail, left, offered = self.run_session({"m0": "inbox", "m1": "inbox", "m2": "inbox"}, [("trash", ["m1"])])
        self.assertEqual(gmail.places, {"m0": "inbox", "m1": "trash", "m2": "inbox"})

    def test_empty_trash_deletes_only_the_trash(self):
        gmail, left, offered = self.run_session({"m0": "inbox", "m1": "archive", "t1": "trash"},
                                                [("empty_trash", [])], api=FakeMailboxApi())
        self.assertEqual(gmail.places, {"m0": "inbox", "m1": "archive", "t1": "gone"})

    def test_trash_command_deletes_only_the_trash(self):
        import io
        from unittest import mock
        from rich.console import Console
        api = FakeMailboxApi()
        api.gmail = FakeGmail({"m0": "inbox", "m1": "archive", "t1": "trash"}, save_dir=None)
        output = io.StringIO()
        test_console = Console(file=output, width=200)
        test_console.input = lambda prompt: "y"
        with mock.patch.object(savegmail, "console", test_console):
            savegmail.empty_trash(api)
        self.assertEqual(api.gmail.places, {"m0": "inbox", "m1": "archive", "t1": "gone"})
        self.assertIn("1 message(s) permanently deleted from trash.", output.getvalue())


class TypedSelectionTest(unittest.TestCase):
    """ask_user_to_select_messages when stdin / stdout are not a terminal (pipe, CI)."""

    def select(self, answers, messages=None):
        import builtins
        from unittest import mock
        messages = make_messages(3) if messages is None else messages
        prompts = []

        def fake_input(prompt=""):
            prompts.append(prompt)
            if not answers:
                raise EOFError
            return answers.pop(0)

        stdin = mock.Mock(isatty=lambda: False)
        with savegmail.console.capture() as out, mock.patch.object(builtins, "input", fake_input), \
                mock.patch.object(savegmail.sys, "stdin", stdin):
            action, chosen = savegmail.ask_user_to_select_messages(messages)
        return action, [message["id"] for message in chosen], prompts, out.get()

    def test_permanent_delete_needs_typed_delete(self):
        for confirm in ("no", "y", "", "Delete"):
            with self.subTest(confirm=confirm):
                action, chosen, prompts, _ = self.select(["D 1", confirm, "q"])
                self.assertEqual((action, chosen), ("quit", []))
                self.assertIn("Type delete:", prompts[1])
        action, chosen, _, _ = self.select(["D 1", "delete"])
        self.assertEqual((action, chosen), ("delete", ["0"]))

    def test_trash_needs_yes(self):
        for confirm in ("n", "", "no"):
            with self.subTest(confirm=confirm):
                action, chosen, prompts, _ = self.select(["d 1", confirm, "q"])
                self.assertEqual((action, chosen), ("quit", []))
                self.assertIn("[y/N]", prompts[1])
        action, chosen, _, _ = self.select(["d 1", "y"])
        self.assertEqual((action, chosen), ("trash", ["0"]))

    def test_end_of_input_during_confirmation_quits(self):
        for command in ("D 1", "d 1"):
            with self.subTest(command=command):
                self.assertEqual(self.select([command])[:2], ("quit", []))

    def test_number_shown_is_email_chosen(self):
        messages = make_messages(3)
        action, chosen, _, output = self.select(["D 2", "delete"], messages)
        self.assertEqual(action, "delete")
        shown = {line.split()[0]: line for line in output.splitlines() if line.strip()}
        subject = next(m["subject"] for m in messages if m["id"] == chosen[0])
        self.assertIn(subject, shown["2"])


FAKE_PYTHON = """#!/bin/sh
printf '%s\\n' "$*" >> "$FAKE_LOG"
if [ "$1" = "-m" ] && [ "$2" = "pip" ]; then
    exit "${FAKE_PIP_RC:-0}"
fi
exit 0
"""


class LauncherUpgradeTest(unittest.TestCase):
    """run-savegmail.sh upgrades an existing .venv weekly, including indirect deps."""

    def setUp(self):
        import shutil
        import tempfile
        if shutil.which("sh") is None or shutil.which("find") is None:
            self.skipTest("sh and find are required")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = self.tmp.name
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        shutil.copy(os.path.join(repo, "run-savegmail.sh"), root)
        os.makedirs(os.path.join(root, ".venv", "bin"))
        python = os.path.join(root, ".venv", "bin", "python")
        with open(python, "w") as handle:
            handle.write(FAKE_PYTHON)
        os.chmod(python, 0o755)
        self.root = root
        self.log = os.path.join(root, "calls.log")
        self.stamp = os.path.join(root, ".venv", ".savegmail-upgraded")

    def launch(self, pip_rc=0):
        import subprocess
        env = dict(os.environ, FAKE_LOG=self.log, FAKE_PIP_RC=str(pip_rc))
        result = subprocess.run(["sh", os.path.join(self.root, "run-savegmail.sh"), "--help"],
                                env=env, capture_output=True, text=True, timeout=30)
        calls = []
        if os.path.exists(self.log):
            with open(self.log) as handle:
                calls = handle.read().splitlines()
            os.remove(self.log)
        return result.returncode, [call for call in calls if call.startswith("-m pip")], calls

    def test_existing_venv_upgrades_dependencies_eagerly(self):
        rc, pip_calls, _ = self.launch()
        self.assertEqual(rc, 0)
        self.assertEqual(len(pip_calls), 1)
        args = pip_calls[0].split()
        self.assertIn("--upgrade", args)
        self.assertIn("eager", args)
        self.assertIn("certifi", args)
        self.assertTrue(os.path.exists(self.stamp))
        rc, pip_calls, _ = self.launch()
        self.assertEqual((rc, pip_calls), (0, []))

    def test_stale_stamp_offline_keeps_launching(self):
        open(self.stamp, "w").close()
        old = 8 * 24 * 3600
        os.utime(self.stamp, (os.path.getmtime(self.stamp) - old,) * 2)
        rc, pip_calls, calls = self.launch(pip_rc=1)
        self.assertEqual(rc, 0)
        self.assertEqual(len(pip_calls), 1)
        self.assertTrue(calls[-1].endswith("savegmail.py --help"))
        rc, pip_calls, _ = self.launch(pip_rc=0)
        self.assertEqual(len(pip_calls), 1)


if __name__ == "__main__":
    unittest.main()
