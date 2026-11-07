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


def screen_after(keys, columns, rows, messages=None, **kwargs):
    """The picker's screen text, columns × rows, once keys are handled; then esc and q close it."""
    import io
    import threading
    import time
    from unittest import mock
    from prompt_toolkit.data_structures import Size
    from prompt_toolkit.output.vt100 import Vt100_Output
    from prompt_toolkit.renderer import Renderer
    render, shown = Renderer.render, {}

    def record(self, app, layout, is_done=False):
        render(self, app, layout, is_done)
        if not is_done:
            buffer = self._last_screen.data_buffer
            shown["text"] = "\n".join(
                "".join(buffer[y][x].char for x in range(max(buffer[y], default=-1) + 1)).rstrip()
                for y in range(rows))

    output = Vt100_Output(io.StringIO(), lambda: Size(rows, columns), term="xterm")
    result, done = {}, threading.Event()
    with mock.patch.object(Renderer, "render", record), create_pipe_input() as pipe:
        with create_app_session(input=pipe, output=output):
            def send():
                time.sleep(0.3)
                pipe.send_text(keys)
                time.sleep(0.5)
                result["text"] = shown.get("text")
                # esc closes a prompt (or the list), q the list; nothing is sent once it is closed.
                for key in ("\x1b", "q"):
                    if not done.wait(0.3):
                        pipe.send_text(key)
            sender = threading.Thread(target=send, daemon=True)
            sender.start()
            savegmail.pick_messages(make_messages(3) if messages is None else messages, **kwargs)
            done.set()
            sender.join()
    return result["text"]


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


class ListCandidatesTest(unittest.TestCase):
    """list_candidate_messages: first page, token for m, and Gmail pages of at most 500."""

    def mailbox(self, count):
        return [(f"m{i}", count - i) for i in range(count)]  # newest first

    def ids(self, messages):
        return [message["id"] for message in messages]

    def test_first_page_leaves_a_token_for_m(self):
        service = FakeListService(self.mailbox(120))
        messages, token = savegmail.list_candidate_messages(service, "me", max_results=50)
        self.assertEqual(self.ids(messages), [f"m{i}" for i in range(50)])
        self.assertIsNotNone(token)
        older, token = savegmail.list_candidate_messages(service, "me", max_results=50, page_token=token)
        self.assertEqual(self.ids(older), [f"m{i}" for i in range(50, 100)])
        self.assertIsNotNone(token)
        last, token = savegmail.list_candidate_messages(service, "me", max_results=50, page_token=token)
        self.assertEqual((self.ids(last), token), ([f"m{i}" for i in range(100, 120)], None))

    def test_more_than_one_gmail_page_has_no_duplicates(self):
        service = FakeListService(self.mailbox(1200))
        messages, token = savegmail.list_candidate_messages(service, "me", max_results=600)
        self.assertEqual(self.ids(messages), [f"m{i}" for i in range(600)])
        self.assertEqual(token, "600")


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

    def test_help_scrolls_when_taller_than_the_screen(self):
        # DummyOutput is 80×40: the wrapped help is taller. The arrows scroll it, any other key closes it.
        state = savegmail.new_picker_state()
        self.assertEqual(pick("?jq\r", state=state), ("download", ["0"]))
        self.assertEqual(state["help_top"], 1)
        pick("?\x1b[F\x1bq", state=state)  # End: down to the last row
        rows = savegmail.help_lines(80)
        self.assertEqual(rows[state["help_top"]:][-1], [("class:key", "  q esc   "), ("", "quit")])
        for row in rows:
            self.assertLessEqual(sum(savegmail.cell_len(text) for _, text in row), 79, row)

    def test_narrow_footer_keeps_main_keys_and_typed_input(self):
        # 80×24 (the default terminal) and below: every footer line fits, the save, view, help and
        # quit keys keep their label, and what is typed (D, T, f, /) stays visible with its cursor.
        def footer(keys, columns, **kwargs):
            lines = screen_after(keys, columns, 24, **kwargs).rstrip("\n").split("\n")[-3:]
            for line in lines:
                self.assertLessEqual(savegmail.cell_len(line), columns - 1, (columns, line))
            return "\n".join(lines)

        for columns in (60, 80, 100):
            text = footer("", columns)
            for part in ("enter save+trash", "s save+keep", "? help", "q quit", "d trash"):
                self.assertIn(part, text, (columns, text))
        text = footer("", 80, views=("All mail", "Trash"), view=1, undo_label="trash (3)")
        for part in ("R restore", "s save+keep", "u undo trash (3)"):
            self.assertIn(part, text)
        self.assertIn("R not spam", footer("", 80, views=("All mail", "Spam"), view=1))
        signed_out = savegmail.new_picker_state()
        signed_out["signed_out"] = True
        text = footer("", 100, state=signed_out, sign_in=lambda: None, load_more=lambda: [])
        for part in ("r sign in", "m more", "enter save+trash", "s save+keep", "q quit"):
            self.assertIn(part, text)
        self.assertIn("Type empty: em▏", footer("Tem", 80))
        self.assertIn("Type delete: del▏", footer("aDdel", 80, messages=make_messages(40)))
        # A path longer than the line: its end, where one types, shows after …
        path = "~/Documents/Archives/Correspondance-administrative/2026/Fournisseurs-et-prestataires/Novembre-a-trier/"
        self.assertRegex(footer("f\x15" + path, 80), r"\n …[^\n]*/Novembre-a-trier/▏\n")
        self.assertRegex(footer("/" + "news" * 30, 80), r" / …w?s?(news)+▏\n enter apply · esc clear")

    def test_long_notice_wraps_instead_of_being_cut(self):
        cause = "Call log: navigating to https://mail.google.com/mail/u/0/#inbox/abcdef, waiting until load"
        notice = [[("class:checked", " ✓ "), ("", "1 saved"), ("class:dim", " · u undo")],
                  [("class:error", " ✗ "), ("", "Subject 0: " + cause)]]
        text = screen_after("", 80, 24, notice=notice)
        self.assertIn("waiting until load", text)
        self.assertIn("1 saved · u undo", text)
        self.assertIn("Subject 0", text)  # the list still shows below the wrapped notice
        self.assertEqual(savegmail.screen_rows(notice[1], 80), 2)

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

    def test_select_all_only_visible(self):
        # Under a filter, a and A only take the emails shown, not the hidden ones.
        messages = make_messages(4)
        messages[3]["from"], messages[3]["subject"] = messages[1]["from"], "Other"
        self.assertEqual(pick("/Subject 1\ra\r", messages), ("download", ["1"]))
        self.assertEqual(pick("/Subject 1\rA\r", messages), ("download", ["1"]))
        self.assertEqual(pick("/Subject 1\raDdelete\r", messages), ("delete", ["1"]))
        # Without the filter, A takes both emails of the sender.
        self.assertEqual(pick("jA\r", messages), ("download", ["1", "3"]))

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

    def test_load_more_keeps_the_cursor_on_its_email_when_sorted_by_size(self):
        messages = make_messages(3)
        for message, size in zip(messages, (10, 30, 20)):
            message["size"] = size
        # z puts "0" last with the cursor on it, k moves to "2"; the older email goes above "2".
        older = [{**make_messages(1)[0], "id": "old", "internalDate": 1, "size": 25}]
        action, ids = pick_later("zkm\r", messages, delay=0.2, load_more=lambda: (older, False))
        self.assertEqual([message["id"] for message in messages], ["0", "1", "2", "old"])
        self.assertEqual((action, ids), ("download", ["2"]))

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

    def test_select_same_recipient_with_comma_in_name(self):
        messages = make_messages(3)
        for message, to in zip(messages, ['"Doe, John" <john@example.com>', '"Doe, Jane" <jane@example.com>',
                                          "Bob <bob@example.com>"]):
            message.update(to=to, labels=["SENT"])
        row = savegmail.message_row(messages[0])
        self.assertEqual((row["sender"], row["party"]), ("Sent · Doe, John", "john@example.com"))
        self.assertEqual(pick("A\r", messages), ("download", ["0"]))

    def test_select_same_sender_keeps_direction(self):
        messages = make_messages(4)
        for i in (0, 2):
            messages[i]["from"] = "Bob <bob@example.com>"
        messages[1].update(to="Bob <bob@example.com>", labels=["SENT"])
        self.assertEqual(pick("A\r", messages), ("download", ["0", "2"]))
        self.assertEqual(pick("jA\r", messages), ("download", ["1"]))

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
        state["cursor_id"] = "0"  # moves from first to last row, so a stale index points elsewhere
        action, ids = pick_later("\r", messages, sync=sync, badges=badges, state=state)
        self.assertEqual(calls, [["0", "1", "2"]])
        self.assertEqual([message["id"] for message in messages], ["new", "1", "0"])  # newest first
        self.assertEqual(next(m for m in messages if m["id"] == "0")["labels"], ["INBOX", "STARRED"])
        self.assertEqual(badges, {"Inbox": ("4", "unread")})
        self.assertEqual((action, ids), ("download", ["0"]))

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

    def test_silent_remote_image_does_not_block_the_save(self):
        import base64
        import socket
        import tempfile
        import threading
        import time
        from unittest import mock
        from playwright.sync_api import sync_playwright
        # Local server that accepts connections and never answers, like a dead tracking-pixel host.
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(16)
        held = []

        def accept():
            try:
                while True:
                    held.append(server.accept()[0])
            except OSError:
                pass

        threading.Thread(target=accept, daemon=True).start()
        port = server.getsockname()[1]
        body = f'<p>Total 42 EUR</p><img src="http://127.0.0.1:{port}/open.gif" width=1 height=1>'
        raw = ("Subject: Pixel\r\nFrom: s@example.com\r\nMIME-Version: 1.0\r\n"
               "Content-Type: text/html; charset=utf-8\r\n\r\n" + body + "\r\n").encode()
        try:
            with sync_playwright() as playwright:
                try:
                    browser = playwright.chromium.launch(channel="chromium")
                except Exception as error:  # no Playwright Chromium here; never install it from a test
                    self.skipTest(f"Chromium unavailable: {error}")
                try:
                    with tempfile.TemporaryDirectory() as save_dir, \
                            mock.patch.object(savegmail, "IMAGE_WAIT_SECONDS", 1, create=True):
                        start = time.monotonic()
                        result = savegmail.save_email_and_attachments(
                            FakeRawService(base64.urlsafe_b64encode(raw).decode()), "me", "id1", save_dir,
                            browser)
                        elapsed = time.monotonic() - start
                        self.assertTrue(os.path.exists(os.path.join(save_dir, result["pdf"])))
                finally:
                    browser.close()
        finally:
            server.close()
            for conn in held:
                conn.close()
        self.assertTrue(held)  # Chromium did ask for the image
        self.assertLess(elapsed, 30)  # it used to wait for the 120 s set_content timeout, then fail


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


class EscapedTextTest(unittest.TestCase):
    """Plain text and header values are text: a `<` or `&` in them is shown, never read as HTML."""

    def test_plain_text_headers_and_attachment_names_are_escaped(self):
        import base64
        import tempfile
        from email.message import EmailMessage
        msg = EmailMessage()
        msg["Subject"] = "Fix List<String> <style>h3~div{display:none}</style>"
        msg["From"] = '"Bank <security@bank.example>" <evil@attacker.test>'
        msg["Reply-To"] = "Alice <alice@example.com>, Dev list <dev@lists.example.org>"
        msg["To"] = "Bob <bob@example.com>"
        msg["Cc"] = "Carol <carol@example.com>"
        msg.set_content("On Mon, Bob <bob@example.com> wrote:\n> if a<b and b>c\n> Tom &copy;\n"
                        "Item   Qty\nSee <https://example.com/a?x=1&y=2> now\n")
        msg.add_attachment(b"x", maintype="text", subtype="plain", filename="Q&A&para2.txt")
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

        browser = OptionsRecordingBrowser()
        with tempfile.TemporaryDirectory() as save_dir:
            savegmail.save_email_and_attachments(
                FakeRawService(base64.urlsafe_b64encode(msg.as_bytes()).decode()), "me", "id1", save_dir,
                browser)
        body, header, footer = browser.pages[0].html, options[0]["header_template"], options[0]["footer_template"]
        self.assertIn("Bob &lt;bob@example.com&gt; wrote:", body)
        self.assertIn("&gt; if a&lt;b and b&gt;c", body)
        self.assertIn("Tom &amp;copy;", body)
        self.assertIn("white-space: pre-wrap", body)  # the spaces that align columns are kept
        self.assertIn('<a href="https://example.com/a?x=1&amp;y=2" target="_blank">', body)
        self.assertIn("Fix List&lt;String&gt; &lt;style&gt;", header)
        self.assertNotIn("<style>", header)
        self.assertIn("Bank &lt;security@bank.example&gt; evil@attacker.test", header)
        self.assertIn("Alice alice@example.com, Dev list dev@lists.example.org", header)
        self.assertIn("Q&amp;A&amp;para2.txt</a>", footer)


class PdfHeaderTest(unittest.TestCase):
    """The PDF prints the subject, sender, date and attachments in its header and footer, with room for them."""

    def test_header_and_footer_are_printed_with_measured_margins(self):
        import base64
        import tempfile
        from email.message import EmailMessage
        msg = EmailMessage()
        msg["Subject"] = "Contrat de bail"
        msg["From"] = "Alice Martin <alice@example.com>"
        msg["Date"] = "Mon, 02 Mar 2026 10:15:00 +0000"
        msg.set_content("alt")
        msg.add_alternative("<p>Corps du contrat</p>", subtype="html")
        msg.add_attachment(b"x", maintype="application", subtype="pdf", filename="bail.pdf")
        options = []

        class MeasuringPage(ContentRecordingPage):
            def evaluate(self, script, *args, **kwargs):
                super().evaluate(script, *args, **kwargs)
                return 100 if "getBoundingClientRect" in script else True  # each template is 100px high

            def pdf(self, path, **kwargs):
                options.append(kwargs)
                super().pdf(path, **kwargs)

        class MeasuringBrowser(ContentRecordingBrowser):
            def new_page(self, **kwargs):
                page = MeasuringPage()
                self.pages.append(page)
                return page

        with tempfile.TemporaryDirectory() as save_dir:
            savegmail.save_email_and_attachments(
                FakeRawService(base64.urlsafe_b64encode(msg.as_bytes()).decode()), "me", "id1", save_dir,
                MeasuringBrowser())
        self.assertEqual(len(options), 1)
        printed = options[0]
        self.assertIs(printed["display_header_footer"], True)
        header, footer = printed["header_template"], printed["footer_template"]
        self.assertIn("Contrat de bail", header)
        self.assertIn("From : Alice Martin alice@example.com", header)
        self.assertIn(f"Date : {savegmail.get_real_date(msg['Date'])}", header)
        self.assertIn("bail.pdf", footer)
        self.assertIn("View in Gmail", footer)
        # Room for the measured templates plus Chromium's 20px edge padding and an 8px gap.
        self.assertEqual(printed["margin"]["top"], "128px")
        self.assertEqual(printed["margin"]["bottom"], "128px")


class SplitBodyTest(unittest.TestCase):
    """A body split into several text parts around an attachment is rendered whole, in order."""

    def render(self, msg):
        import base64
        import tempfile
        browser = ContentRecordingBrowser()
        with tempfile.TemporaryDirectory() as save_dir:
            savegmail.save_email_and_attachments(
                FakeRawService(base64.urlsafe_b64encode(msg.as_bytes()).decode()), "me", "id1", save_dir,
                browser)
            saved = sorted(os.listdir(save_dir))
        return browser.pages[0].html, saved

    def test_every_inline_text_part_is_rendered(self):
        from email.message import EmailMessage, MIMEPart
        # Apple Mail, a file placed inside the text: alternative { plain, mixed { html, pdf, html } }.
        msg = EmailMessage()
        msg["Subject"] = "Devis"
        msg["From"] = "Alice <alice@example.com>"
        plain, mixed = MIMEPart(), MIMEPart()
        plain.set_content("Bonjour, voici le devis.\nMerci de signer avant vendredi.\n")
        first, last = MIMEPart(), MIMEPart()
        first.set_content("<html><body><p>Bonjour, voici le devis.</p></body></html>", subtype="html")
        last.set_content("<html><body><p>Merci de signer avant vendredi, montant 4 200 EUR.</p></body></html>",
                         subtype="html")
        mixed.make_mixed()
        mixed.attach(first)
        mixed.add_attachment(b"%PDF-1.4", maintype="application", subtype="pdf", filename="devis.pdf")
        mixed.attach(last)
        msg.make_alternative()
        msg.attach(plain)
        msg.attach(mixed)
        body, saved = self.render(msg)
        self.assertLess(body.index("voici le devis"), body.index("avant vendredi, montant 4 200 EUR"))
        self.assertNotIn("Merci de signer avant vendredi.\n", body)  # the plain alternative is not added
        self.assertIn("devis.pdf", saved)

        # Mailing list footer in its own part: mixed { plain, plain }.
        msg = EmailMessage()
        msg["Subject"] = "Release"
        msg.set_content("The release is out.\n")
        footer = MIMEPart()
        footer.set_content("dev mailing list\nUnsubscribe: https://lists.example.org/u\n")
        msg.make_mixed()
        msg.attach(footer)
        body, saved = self.render(msg)
        self.assertLess(body.index("The release is out."), body.index("Unsubscribe:"))
        self.assertEqual(body.count("white-space: pre-wrap"), 2)

    def test_named_text_part_stays_an_attachment(self):
        from email.message import EmailMessage
        msg = EmailMessage()
        msg["Subject"] = "Notes"
        msg.set_content("See the notes.\n")
        msg.add_attachment("secret notes\n", filename="notes.txt")
        msg.add_attachment("inline but named\n", filename="inline.txt", disposition="inline")
        body, saved = self.render(msg)
        self.assertIn("See the notes.", body)
        self.assertNotIn("secret notes", body)
        self.assertNotIn("inline but named", body)
        self.assertEqual(saved[-2:], ["inline.txt", "notes.txt"])


class BodyCharsetTest(unittest.TestCase):
    """A body without a charset, or with one Python does not know, is still decoded and saved."""

    def render(self, raw):
        import base64
        import tempfile
        browser = ContentRecordingBrowser()
        with tempfile.TemporaryDirectory() as save_dir:
            savegmail.save_email_and_attachments(
                FakeRawService(base64.urlsafe_b64encode(raw).decode()), "me", "id1", save_dir, browser)
        return browser.pages[0].html

    def message(self, content_type, body):
        return (b"Subject: Commande\r\nContent-Type: " + content_type
                + b"\r\nContent-Transfer-Encoding: 8bit\r\n\r\n" + body + b"\r\n")

    def test_missing_or_unknown_charset(self):
        utf8 = "Livrée à Besançon : 129,90 €".encode("utf-8")
        html_body = self.render(self.message(
            b"text/html", b'<html><head><meta charset="utf-8"></head><body>' + utf8 + b"</body></html>"))
        self.assertIn("Livrée à Besançon : 129,90 €", html_body)
        latin = "Livrée à Besançon".encode("latin-1")
        html_body = self.render(self.message(
            b"text/html", b'<html><head><meta http-equiv="Content-Type" content="text/html; '
                          b'charset=iso-8859-1"></head><body>' + latin + b"</body></html>"))
        self.assertIn("Livrée à Besançon", html_body)
        self.assertIn("Livrée à Besançon : 129,90 €", self.render(self.message(b"text/plain", utf8)))
        self.assertIn("Café", self.render(self.message(b"text/plain; charset=unknown-8bit", "Café".encode())))
        self.assertIn("Café", self.render(self.message(b"text/plain; charset=x-mac-roman", b"Caf\x8e")))
        self.assertIn("Café", self.render(self.message(b"text/plain; charset=x-user-defined", b"Caf\xe9")))
        # A declared charset that Python knows is still the one used.
        self.assertIn("Café", self.render(self.message(b"text/plain; charset=iso-8859-1", b"Caf\xe9")))


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

    def test_attached_email_saved_as_eml(self):
        import base64
        import tempfile
        from email import message_from_bytes, policy
        from email.message import EmailMessage
        from unittest import mock
        inner = EmailMessage()
        inner["Subject"] = "Original"
        inner["From"] = "Bob <bob@example.com>"
        inner.set_content("inner body")
        inner.add_attachment(b"%PDF-INNER", maintype="application", subtype="pdf", filename="inner.pdf")
        msg = EmailMessage()
        msg["Subject"] = "Fwd"
        msg["From"] = "Sender <s@example.com>"
        msg.set_content("see attached")
        msg.add_attachment(inner, filename="Original.eml")  # Gmail's "Forward as attachment"
        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
        with tempfile.TemporaryDirectory() as save_dir, \
                mock.patch.object(savegmail, "measure_pdf_margins", return_value={}):
            result = savegmail.save_email_and_attachments(
                FakeRawService(raw), "me", "id1", save_dir, FakePdfBrowser())
            # The attached email is one file; its own parts stay inside it.
            self.assertEqual(result["attachments"], 1)
            self.assertEqual(sorted(os.listdir(save_dir)), sorted([result["pdf"], "Original.eml"]))
            saved = message_from_bytes(self.read(os.path.join(save_dir, "Original.eml")), policy=policy.default)
            self.assertEqual(saved["Subject"], "Original")
            self.assertEqual(saved.get_body(("plain",)).get_content().strip(), "inner body")
            inner_pdf = next(part for part in saved.iter_attachments())
            self.assertEqual(inner_pdf.get_content(), b"%PDF-INNER")


class AttachmentPartTest(unittest.TestCase):
    """Which parts of an email are files written next to its PDF."""

    def save(self, msg, save_attachments=True):
        import base64
        import tempfile
        from unittest import mock
        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
        with tempfile.TemporaryDirectory() as save_dir, \
                mock.patch.object(savegmail, "measure_pdf_margins", return_value={}):
            result = savegmail.save_email_and_attachments(
                FakeRawService(raw), "me", "id1", save_dir, FakePdfBrowser(), save_attachments=save_attachments)
            files = {}
            for name in os.listdir(save_dir):
                if name != result["pdf"]:
                    with open(os.path.join(save_dir, name), "rb") as f:
                        files[name] = f.read()
            return result, files

    def email(self):
        from email.message import EmailMessage
        msg = EmailMessage()
        msg["Subject"] = "Scan"
        msg["From"] = "Sender <s@example.com>"
        msg.set_content("See attached.")
        return msg

    def test_named_attachment_inline_or_without_disposition_is_saved(self):
        for disposition in ("attachment", "inline", None):
            with self.subTest(disposition=disposition):
                msg = self.email()
                msg.add_attachment(b"%PDF-CONTRACT", maintype="application", subtype="pdf",
                                   filename="contrat.pdf", disposition=disposition or "attachment")
                part = list(msg.iter_parts())[-1]
                if disposition is None:  # only `Content-Type: …; name=` (older clients, generated mail)
                    del part["Content-Disposition"]
                    part.set_param("name", "contrat.pdf")
                result, files = self.save(msg)
                self.assertEqual(result["attachments"], 1)
                self.assertEqual(files, {"contrat.pdf": b"%PDF-CONTRACT"})

    def test_attachment_without_name_is_saved(self):
        from email.message import EmailMessage
        inner = EmailMessage()
        inner["Subject"] = "Original"
        inner.set_content("inner body")
        inner.add_attachment(b"%PDF-INNER", maintype="application", subtype="pdf", filename="inner.pdf")
        msg = self.email()
        msg.add_attachment(b"%PDF-SCAN", maintype="application", subtype="pdf")
        msg.add_attachment(b"\x00\x01", maintype="application", subtype="octet-stream")
        msg.add_attachment(inner)  # an attached email without a name: one file, its parts inside it
        result, files = self.save(msg)
        self.assertEqual(result["attachments"], 3)
        self.assertEqual(sorted(files), ["attachment.bin", "attachment.eml", "attachment.pdf"])
        self.assertEqual(files["attachment.pdf"], b"%PDF-SCAN")
        self.assertEqual(files["attachment.bin"], b"\x00\x01")
        self.assertIn(b"inner body", files["attachment.eml"])
        # The preview lists them too, without writing them.
        result, files = self.save(msg, save_attachments=False)
        self.assertEqual((result["attachments"], files), (3, {}))


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


class FailingBatchService(FakeSaveService):
    """The batch call itself fails (503); entries retried one by one fail too, except the ids in ok."""

    def __init__(self, ok=(), error=None):
        super().__init__(raw="")
        self.ok = set(ok)
        self.error = error

    def new_batch_http_request(self, callback):
        from unittest import mock

        class Batch:
            def add(self, request, request_id):
                pass

            def execute(self):
                raise savegmail.HttpError(mock.Mock(status=503, reason="Backend Error"), b"Backend Error")
        return Batch()

    def trash(self, userId, id):
        service = self
        request = super().trash(userId, id)

        class Request:
            def execute(self):
                if id in service.ok:
                    return request.execute()
                service.trashed.append(f"tried {id}")
                from unittest import mock
                raise service.error or savegmail.HttpError(mock.Mock(status=503, reason="Backend Error"),
                                                           b"Backend Error")
        return Request()


class BatchCallFailureTest(unittest.TestCase):
    def test_enter_removes_files_when_trash_batch_fails(self):
        import io
        import tempfile
        from unittest import mock

        def fake_save(service, user_id, msg_id, save_dir, browser, on_step):
            path = os.path.join(save_dir, f"{msg_id}.pdf")
            open(path, "w").close()
            return {"files": [path], "attachments": 0}

        messages = [{"id": msg_id, "from": "S <s@example.com>", "subject": msg_id, "snippet": "",
                     "internalDate": 1_700_000_000_000} for msg_id in ("x", "y")]
        service = FailingBatchService(ok={"y"})
        with tempfile.TemporaryDirectory() as save_dir, \
                mock.patch.object(savegmail, "save_email_and_attachments", fake_save), \
                mock.patch.object(savegmail, "console", savegmail.Console(file=io.StringIO())):
            saved, _, failed, files = savegmail.save_messages(service, "me", messages, save_dir, None, True)
            self.assertEqual(sorted(os.listdir(save_dir)), ["y.pdf"])
        self.assertEqual([message["id"] for message in saved], ["y"])
        self.assertEqual(list(failed), ["x"])
        self.assertIn("could not move to trash", failed["x"])
        self.assertEqual(list(files), ["y"])

    def test_trash_batch_failure_returns_errors(self):
        errors = savegmail.trash_messages(FailingBatchService(), "me", ["x", "y"])
        self.assertEqual(set(errors), {"x", "y"})
        self.assertIsInstance(errors["x"], savegmail.HttpError)

    def test_network_down_stops_the_retries(self):
        service = FailingBatchService(error=OSError("timed out"))
        errors = savegmail.trash_messages(service, "me", ["x", "y", "z"])
        self.assertEqual(set(errors), {"x", "y", "z"})
        self.assertEqual(service.trashed, ["tried x"])


class SaveCleanupTest(unittest.TestCase):
    """A failed or interrupted save leaves no file of that email, and only saved emails go to the trash."""

    messages = [{"id": msg_id, "from": "S <s@example.com>", "subject": msg_id, "snippet": "",
                 "internalDate": 1_700_000_000_000} for msg_id in ("a", "b", "c", "d")]

    @staticmethod
    def fake_save(error_for):
        def save(service, user_id, msg_id, save_dir, browser, on_step, **kwargs):
            if msg_id in error_for:
                raise error_for[msg_id]
            path = os.path.join(save_dir, f"{msg_id}.pdf")
            open(path, "w").close()
            return {"pdf": f"{msg_id}.pdf", "files": [path], "attachments": 0}
        return save

    def save_messages(self, error_for, save_dir):
        import io
        from unittest import mock
        service = FakeSaveService(raw="")
        with mock.patch.object(savegmail, "save_email_and_attachments", self.fake_save(error_for)), \
                mock.patch.object(savegmail, "console", savegmail.Console(file=io.StringIO())):
            try:
                return service, savegmail.save_messages(service, "me", self.messages, save_dir, None, True)
            except KeyboardInterrupt:  # escaping, it would stop the whole test run
                self.fail("Ctrl+C escaped save_messages")

    def save_one(self, save_dir, page_error):
        import base64
        from email.message import EmailMessage
        from unittest import mock

        class FailingPage(FakePdfPage):
            def pdf(self, path, **kwargs):
                open(path, "wb").close()
                raise page_error

        class FailingBrowser:
            def new_page(self, **kwargs):
                return FailingPage(False)

        msg = EmailMessage()
        msg["Subject"] = "Invoice"
        msg["From"] = "Sender <s@example.com>"
        msg.set_content("hello")
        msg.add_attachment(b"data", maintype="application", subtype="octet-stream", filename="data.bin")
        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
        with mock.patch.object(savegmail, "measure_pdf_margins", return_value={}):
            savegmail.save_email_and_attachments(FakeRawService(raw), "me", "id1", save_dir, FailingBrowser())

    def test_failed_save_is_not_trashed(self):
        import tempfile
        with tempfile.TemporaryDirectory() as save_dir:
            service, (saved, _, failed, files) = self.save_messages({"b": RuntimeError("timeout")}, save_dir)
            self.assertEqual(sorted(os.listdir(save_dir)), ["a.pdf", "c.pdf", "d.pdf"])
        self.assertEqual(service.trashed, ["a", "c", "d"])
        self.assertEqual([message["id"] for message in saved], ["a", "c", "d"])
        self.assertEqual(list(failed), ["b"])

    def test_failed_render_removes_attachments(self):
        import tempfile
        with tempfile.TemporaryDirectory() as save_dir:
            with self.assertRaises(Exception):
                self.save_one(save_dir, ValueError("render failed"))
            self.assertEqual(os.listdir(save_dir), [])

    def test_ctrl_c_during_render_removes_partial_files(self):
        import tempfile
        with tempfile.TemporaryDirectory() as save_dir:
            with self.assertRaises(KeyboardInterrupt):
                self.save_one(save_dir, KeyboardInterrupt())
            self.assertEqual(os.listdir(save_dir), [])

    def test_ctrl_c_stops_and_trashes_the_saved_ones(self):
        import tempfile
        with tempfile.TemporaryDirectory() as save_dir:
            service, (saved, _, failed, files) = self.save_messages({"c": KeyboardInterrupt()}, save_dir)
            self.assertEqual(sorted(os.listdir(save_dir)), ["a.pdf", "b.pdf"])
        self.assertEqual(service.trashed, ["a", "b"])  # c (interrupted) and d stay in Gmail
        self.assertEqual([message["id"] for message in saved], ["a", "b"])
        self.assertEqual((failed, sorted(files)), ({}, ["a", "b"]))

    def test_ctrl_c_stops_the_preview(self):
        import io
        import tempfile
        from unittest import mock
        with tempfile.TemporaryDirectory() as preview_dir, \
                mock.patch.object(savegmail, "save_email_and_attachments",
                                  self.fake_save({"b": RuntimeError("timeout"), "c": KeyboardInterrupt()})), \
                mock.patch.object(savegmail, "open_quietly") as opened_files, \
                mock.patch.object(savegmail, "console", savegmail.Console(file=io.StringIO())):
            try:
                opened, failed = savegmail.preview_messages(None, "me", self.messages, None, preview_dir)
            except KeyboardInterrupt:  # escaping, it would stop the whole test run
                self.fail("Ctrl+C escaped preview_messages")
        self.assertEqual((opened, list(failed)), (["a"], ["b"]))
        self.assertEqual(opened_files.call_count, 1)


class FakeGmail:
    """Where each email is in a fake Gmail: inbox, archive, trash or gone (permanently deleted)."""

    def __init__(self, places, save_dir, failing_untrash=(), failing=()):
        self.places, self.save_dir, self.failing_untrash = dict(places), save_dir, set(failing_untrash)
        self.failing = set(failing)  # emails whose save or move to trash fails

    def message(self, msg_id):
        return {"id": msg_id, "from": f"S <{msg_id}@example.com>", "subject": f"Subject {msg_id}",
                "snippet": "", "internalDate": 1_700_000_000_000,
                "labels": ["INBOX"] if self.places.get(msg_id) == "inbox" else []}

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

    def run_session(self, places, steps, failing_untrash=(), failing=(), api=None, down=None, launch=None,
                    args=(), gmail_class=None):
        """steps: (action, ids); an undo is only pressed when u is offered, as in the list.
        ids None: every email the list shows (a then the action).

        api: a fake Gmail API (FakeBatchApi) that the real modify_labels and delete_messages call.
        down: (n, exception): once n steps are done, every Gmail call raises it (session expired, offline);
        self.signed_out holds whether the list offered r to sign in again, before each step.
        launch: replaces launch_browser (default: a new mock browser each time).
        ids {"select": [...], "cursor": id}: space on those emails, then the key, which acts on the
        selection, or on the email under the cursor when nothing is selected (like chosen() in the list).
        Returns (fake Gmail, files left in the download folder, undo label offered before each step);
        self.notices holds the notice shown before each step, as plain text lines; self.marked the ids
        shown ✓, and self.selected those selected, before each step; self.saved the ids passed to each
        save_messages call.
        """
        import io
        import tempfile
        from unittest import mock
        from rich.console import Console
        save_dir = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, save_dir, True)
        gmail = (gmail_class or FakeGmail)(places, save_dir, failing_untrash, failing)
        if api is not None:
            api.gmail = gmail
        steps, offered, self.notices, self.signed_out = list(steps), [], [], []
        self.marked, self.selected, self.saved = [], [], []
        broken = []

        def ask(messages, load_more, state, notice, undo_label, *rest):
            if down is not None and len(offered) == down[0]:
                broken.append(down[1])
            offered.append(undo_label)
            self.signed_out.append(state["signed_out"])
            self.notices.append(["".join(text for _, text in line) for line in notice])
            self.marked.append(sorted(state["saved"]))
            self.selected.append(sorted(state["selected"]))
            if not steps:
                return "quit", []
            action, ids = steps.pop(0)
            if action == "undo" and undo_label is None:
                return ask(messages, load_more, state, notice, undo_label, *rest)
            if action == "folder":  # ids: the folder typed after f
                state["folder"] = ids
                return action, []
            if ids is None:
                return action, list(messages)
            if isinstance(ids, dict):
                state["selected"] |= set(ids.get("select", ()))
                ids = sorted(state["selected"]) or [ids["cursor"]]
            return action, [gmail.message(msg_id) for msg_id in ids]

        fakes = {name: getattr(gmail, name) for name in [
            "list_candidate_messages", "save_messages", "trash_messages", "untrash_messages",
            "modify_labels", "list_trash_ids", "delete_messages"]
            if api is None or name not in api.real_calls}

        def recorded(call, calls, ids_of):
            def wrapper(*args, **kwargs):
                calls.append(ids_of(*args))
                return call(*args, **kwargs)
            return wrapper
        fakes["save_messages"] = recorded(fakes["save_messages"], self.saved,
                                          lambda service, user_id, messages, *rest: [m["id"] for m in messages])

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
            sync_playwright=lambda: FakePlaywright(), launch_browser=launch or (lambda *a, **k: mock.Mock()),
            open_quietly=lambda url: True, console=Console(file=io.StringIO()), **fakes,
        ), mock.patch.object(sys, "argv", ["savegmail", "--download-path", save_dir, *args]):
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

    def test_crashed_chromium_is_started_again(self):
        from unittest import mock
        launched = []

        def launch(*args, **kwargs):
            browser = mock.Mock()
            if not launched:
                # Killed between two saves: is_connected() still says True until the next round trip.
                browser.is_connected.return_value = True
                browser.new_browser_cdp_session.side_effect = savegmail.PlaywrightError("Target closed")
            launched.append(browser)
            return browser

        self.run_session({"A": "inbox", "B": "inbox", "C": "inbox"},
                         [("save", ["A"]), ("save", ["B"]), ("save", ["C"])], launch=launch)
        self.assertEqual(len(launched), 2)

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

    def test_archive_undo_only_puts_back_emails_that_were_in_the_inbox(self):
        # e in All mail on an Inbox email and a sent or already archived one: u only undoes the first.
        gmail, left, offered = self.run_session({"A": "inbox", "S": "archive"},
                                                [("archive", ["A", "S"]), ("undo", [])])
        self.assertEqual(offered[1], "archive (1)")
        self.assertEqual(gmail.places, {"A": "inbox", "S": "archive"})
        self.assertEqual(self.notices[2][0], " ↶ 1 email back in the Inbox")

    def test_tilde_download_folders_are_under_home(self):
        # The default ~/GMail/ and a folder typed after f in ~/... are written under HOME, not in a "~"
        # folder of the directory savegmail was started from.
        import tempfile
        from unittest import mock
        home, cwd = tempfile.mkdtemp(), tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, home, True)
        self.addCleanup(__import__("shutil").rmtree, cwd, True)
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(cwd)
        with mock.patch.dict(os.environ, {"HOME": home}):
            gmail, left, offered = self.run_session(
                {"A": "inbox", "B": "inbox"},
                [("download", ["A"]), ("folder", " ~/Archive "), ("download", ["B"])],
                args=["--download-path", savegmail.DOWNLOAD_PATH])
        self.assertEqual(sorted(os.listdir(os.path.join(home, "GMail"))), ["A-att.bin", "A.pdf"])
        self.assertEqual(sorted(os.listdir(os.path.join(home, "Archive"))), ["B-att.bin", "B.pdf"])
        self.assertEqual(os.listdir(cwd), [])
        self.assertEqual(self.notices[2][0], " ✓ Download folder: ~/Archive")

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


class SaveMarksTest(unittest.TestCase):
    """s keeps the emails in Gmail, marked ✓ in every view and no longer selected; u takes back only its own ✓."""

    run_session = UndoAfterDeleteTest.run_session

    def test_save_clears_the_selection_so_enter_acts_on_the_cursor(self):
        gmail, left, offered = self.run_session(
            {"A": "inbox", "B": "inbox", "X": "inbox"},
            [("save", {"select": ["A", "B"], "cursor": "A"}), ("download", {"cursor": "X"})])
        self.assertEqual(self.selected[1], [])
        self.assertEqual(self.saved, [["A", "B"], ["X"]])
        self.assertEqual(gmail.places, {"A": "inbox", "B": "inbox", "X": "trash"})

    def test_save_marks_the_email_in_every_view(self):
        self.run_session({"A": "inbox"}, [("save", ["A"]), ("next_view", []), ("next_view", [])])
        # All mail, where s was pressed, then Inbox and Archived.
        self.assertEqual(self.marked[1:], [["A"], ["A"], ["A"]])

    def test_undo_of_save_removes_the_mark_in_every_view(self):
        self.run_session({"A": "inbox"}, [("save", ["A"]), ("undo", []), ("next_view", [])])
        self.assertEqual(self.marked[1:], [["A"], [], []])

    def test_undo_keeps_the_mark_of_an_earlier_save(self):
        cases = {"enter": ([("save", ["A"]), ("download", ["A"]), ("undo", [])], ["A"]),
                 "s again": ([("save", ["A"]), ("save", ["A"]), ("undo", [])], ["A"]),
                 "D on another email": ([("save", ["A"]), ("delete", ["B"]), ("undo", [])], [])}
        for name, (steps, marked) in cases.items():
            with self.subTest(name):
                gmail, left, offered = self.run_session({"A": "inbox", "B": "inbox"}, steps)
                self.assertEqual(offered[3], None)  # u was pressed
                self.assertEqual(self.marked[3], marked)


class SelectionAfterActionTest(unittest.TestCase):
    """d, D, enter and e take the emails they handled out of the selection: the next key acts on the cursor."""

    run_session = UndoAfterDeleteTest.run_session
    places = {"A": "inbox", "B": "inbox", "X": "inbox"}
    batch = {"select": ["A", "B"], "cursor": "A"}

    def test_trash_then_undo_then_delete_deletes_only_the_cursor_email(self):
        gmail, left, offered = self.run_session(
            self.places, [("trash", self.batch), ("undo", []), ("delete", {"cursor": "X"})])
        self.assertEqual(self.selected[1:], [[], [], []])
        self.assertEqual(gmail.places, {"A": "inbox", "B": "inbox", "X": "gone"})

    def test_archive_then_undo_then_trash_trashes_only_the_cursor_email(self):
        gmail, left, offered = self.run_session(
            self.places, [("next_view", []), ("archive", self.batch), ("undo", []), ("trash", {"cursor": "X"})])
        self.assertEqual(self.selected[2:], [[], [], []])
        self.assertEqual(gmail.places, {"A": "inbox", "B": "inbox", "X": "trash"})

    def test_delete_then_trash_trashes_the_cursor_email(self):
        gmail, left, offered = self.run_session(self.places, [("delete", self.batch), ("trash", {"cursor": "X"})])
        self.assertEqual(self.selected[1], [])
        self.assertEqual(gmail.places, {"A": "gone", "B": "gone", "X": "trash"})

    def test_save_and_trash_then_archive_archives_the_cursor_email(self):
        gmail, left, offered = self.run_session(self.places, [("download", self.batch), ("archive", {"cursor": "X"})])
        self.assertEqual(self.selected[1], [])
        self.assertEqual(self.saved, [["A", "B"]])
        self.assertEqual(gmail.places, {"A": "trash", "B": "trash", "X": "archive"})


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


class SpamMailboxApi(FakeMailboxApi):
    """FakeMailboxApi where an email only leaves the Spam when SPAM is removed, as in Gmail's Spam view."""

    def batchModify(self, userId, body):
        def place(msg_id):
            if self.gmail.places[msg_id] == "spam" and "SPAM" not in body["removeLabelIds"]:
                return "spam"
            if "INBOX" in body["addLabelIds"]:
                return "inbox"
            return "archive" if "INBOX" in body["removeLabelIds"] else self.gmail.places[msg_id]
        return self.request("batchModify", body["ids"], place)


class RestoreKeyTest(unittest.TestCase):
    """R in Spam, Archived and Trash puts the chosen email back in the Inbox, and only that one."""

    run_session = UndoAfterDeleteTest.run_session

    def test_not_spam_moves_the_email_out_of_spam_to_the_inbox(self):
        gmail, left, offered = self.run_session({"s0": "spam", "s1": "spam"}, [("not_spam", ["s1"])],
                                                api=SpamMailboxApi())
        self.assertEqual(gmail.places, {"s0": "spam", "s1": "inbox"})
        self.assertEqual(self.notices[1][0], " ✓ 1 email moved to the Inbox")

    def test_unarchive_moves_the_email_to_the_inbox(self):
        gmail, left, offered = self.run_session({"a0": "archive", "a1": "archive"}, [("unarchive", ["a1"])],
                                                api=SpamMailboxApi())
        self.assertEqual(gmail.places, {"a0": "archive", "a1": "inbox"})
        self.assertEqual(self.notices[1][0], " ✓ 1 email moved to the Inbox")

    def test_restore_takes_the_email_out_of_the_trash(self):
        gmail, left, offered = self.run_session({"t0": "trash", "t1": "trash"}, [("restore", ["t1"])])
        self.assertEqual(gmail.places, {"t0": "trash", "t1": "inbox"})
        self.assertEqual(self.notices[1][0], " ↶ 1 email restored from trash")


class SyncedMailboxApi(FakeService):
    """Gmail API over {id: labels}: messages.get gives the labels, labels.get and messages.list the counters."""

    def __init__(self, labels):
        super().__init__()
        self.mail = labels

    def users(self):
        return self

    def messages(self):
        return self

    def labels(self):
        api = self

        class Labels:
            def get(self, userId, id):
                tagged = [labels for labels in api.mail.values() if id in labels]
                return FakeResult({"id": id, "messagesTotal": len(tagged),
                                   "messagesUnread": sum("UNREAD" in labels for labels in tagged)})
        return Labels()

    def getProfile(self, userId):
        return FakeResult({"emailAddress": "me@example.com"})

    def get(self, userId, id, format, fields):
        return FakeResult({"id": id, "labelIds": list(self.mail[id])})

    def list(self, userId, q="", maxResults=100, pageToken=None, fields=None, **kwargs):
        ids = [msg_id for msg_id, labels in self.mail.items()
               if ("is:unread" not in q or "UNREAD" in labels) and ("-in:inbox" not in q or "INBOX" not in labels)]
        return FakeResult({"messages": [{"id": msg_id} for msg_id in ids], "resultSizeEstimate": len(ids)})


class BackgroundSyncSessionTest(unittest.TestCase):
    """The sync interactive_download_main hands the list re-reads labels and tab counters from Gmail."""

    def test_sync_reads_labels_and_badges_changed_elsewhere(self):
        import io
        import tempfile
        from unittest import mock
        from rich.console import Console
        save_dir = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, save_dir, True)
        api = SyncedMailboxApi({msg_id: ["INBOX", "UNREAD"] for msg_id in ["m0", "m1", "m2"]})
        results = []

        def listed(*args, **kwargs):
            return [{"id": msg_id, "from": f"S <{msg_id}@example.com>", "subject": f"Subject {msg_id}",
                     "snippet": "", "internalDate": 1_700_000_000_000, "labels": list(labels)}
                    for msg_id, labels in api.mail.items()], None

        def ask(messages, load_more, state, notice, undo_label, total, views, view, badges, folder, sync, *rest):
            if not results:
                api.mail["m1"] = ["INBOX"]  # read on the phone
                api.mail["m2"] = ["INBOX", "UNREAD", "STARRED"]  # starred in Gmail web
                results.append(sync([dict(message) for message in messages]))
            return "quit", []

        with mock.patch.multiple(
            savegmail, authenticate=lambda: object(), build=lambda *a, **k: api, user_labels=lambda *a: {},
            list_candidate_messages=listed, ask_user_to_select_messages=ask,
            refresh_messages=lambda *a, **k: ([], set()), sync_playwright=lambda: FakePlaywright(),
            launch_browser=lambda *a, **k: mock.Mock(), open_quietly=lambda url: True,
            console=Console(file=io.StringIO()),
        ), mock.patch.object(sys, "argv", ["savegmail", "--download-path", save_dir]):
            savegmail.interactive_download_main()
        result = results[0]
        self.assertEqual(result["labels"]["m1"], ["INBOX"])
        self.assertEqual(result["labels"]["m2"], ["INBOX", "UNREAD", "STARRED"])
        self.assertEqual(result["labels"]["m0"], ["INBOX", "UNREAD"])
        self.assertEqual(result["badges"]["Inbox"], ("2", "unread"))
        self.assertEqual(result["badges"]["Starred"], ("1", "unread"))
        self.assertEqual(result["badges"]["All mail"], ("2", "unread"))


class LoadMoreSessionTest(unittest.TestCase):
    """m as interactive_download_main builds it: before:<seconds> from the view floor, known ids dropped."""

    # Newest first, internalDate in ms; m3 and m4 share a second across the first page boundary.
    MAILBOX = [("m1", 10_000_000), ("m2", 9_000_000), ("m3", 8_000_700), ("m4", 8_000_200),
               ("m5", 7_000_000), ("m6", 6_000_000), ("m7", 5_000_000), ("m8", 4_000_000)]

    def test_repeated_m_loads_every_older_email_once(self):
        import io
        import re
        import tempfile
        from unittest import mock
        from rich.console import Console
        save_dir = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, save_dir, True)
        first, loads, queries = [], [], []

        def listed(service, user_id, query="", max_results=50, page_token=None, in_trash=False):
            # Gmail's before:<epoch seconds> is exclusive; no page token here, m relies on before: only.
            queries.append(query)
            match = re.search(r"before:(\d+)", query)
            matching = [(msg_id, date) for msg_id, date in self.MAILBOX
                        if match is None or date < int(match.group(1)) * 1000]
            page = matching[:max_results]
            return ([{"id": msg_id, "from": f"S <{msg_id}@example.com>", "subject": msg_id, "snippet": "",
                      "internalDate": date, "labels": ["INBOX"]} for msg_id, date in page],
                    "next" if len(matching) > max_results else None)

        def ask(messages, load_more, *rest):
            first.extend(message["id"] for message in messages)
            more = load_more is not None
            while more and len(loads) < 10:
                older, more, *loaded = load_more()  # as the list does on m
                loads.append(([message["id"] for message in older], more))
                messages.extend(older)
                for done in loaded:
                    done()
            return "quit", []

        with mock.patch.multiple(
            savegmail, authenticate=lambda: object(), build=lambda *a, **k: FakeSessionService(),
            user_labels=lambda *a: {}, estimate_total=lambda *a, **k: None, list_candidate_messages=listed,
            ask_user_to_select_messages=ask, refresh_messages=lambda *a, **k: ([], set()),
            sync_playwright=lambda: FakePlaywright(), launch_browser=lambda *a, **k: mock.Mock(),
            open_quietly=lambda url: True, console=Console(file=io.StringIO()),
        ), mock.patch.object(sys, "argv", ["savegmail", "--download-path", save_dir, "--max", "3"]):
            savegmail.interactive_download_main()

        self.assertEqual(first, ["m1", "m2", "m3"])
        self.assertEqual(loads, [(["m4", "m5"], True), (["m6", "m7"], True), (["m8"], False)])
        dates = dict(self.MAILBOX)
        shown = list(first)
        for older, _ in loads:  # each m: new emails, all older than everything listed before
            self.assertTrue(older)
            self.assertLess(max(dates[msg_id] for msg_id in older), min(dates[msg_id] for msg_id in shown))
            shown += older
        self.assertEqual(shown, [msg_id for msg_id, _ in self.MAILBOX])  # none twice, none skipped
        self.assertEqual(queries[1:], ["before:8001", "before:7001", "before:5001"])


class LabelGmail(FakeGmail):
    """FakeGmail whose emails also carry UNREAD / STARRED: m0 starred, m1 and m2 unread, all in the Inbox."""

    def __init__(self, *args):
        super().__init__(*args)
        self.labels = {"m0": {"STARRED"}, "m1": {"UNREAD"}, "m2": {"UNREAD"}}

    def message(self, msg_id):
        message = super().message(msg_id)
        message["labels"] += sorted(self.labels[msg_id])
        return message


class LabelMailboxApi(FakeMailboxApi):
    """FakeMailboxApi whose batchModify also adds / removes UNREAD and STARRED on a LabelGmail."""

    def batchModify(self, userId, body):
        from unittest import mock
        request = super().batchModify(userId, body)

        def execute():
            result = request.execute()
            for msg_id in body["ids"]:
                labels = self.gmail.labels[msg_id]
                labels |= set(body["addLabelIds"]) - {"INBOX"}
                labels -= set(body["removeLabelIds"])
            return result
        return mock.Mock(execute=execute)


class LabelKeyTargetsTest(unittest.TestCase):
    """e, !, *, o and p change the chosen email only, never the rest of the view."""

    run_session = UndoAfterDeleteTest.run_session

    def labels_after(self, action):
        gmail, left, offered = self.run_session({"m0": "inbox", "m1": "inbox", "m2": "inbox"}, [(action, ["m1"])],
                                                api=LabelMailboxApi(), gmail_class=LabelGmail)
        return gmail

    def test_archive_moves_only_the_chosen_email(self):
        gmail = self.labels_after("archive")
        self.assertEqual(gmail.places, {"m0": "inbox", "m1": "archive", "m2": "inbox"})
        self.assertEqual(self.notices[1][0], " ✓ 1 email archived · u undo")

    def test_read_state_changes_only_on_the_chosen_email(self):
        gmail = self.labels_after("unread")
        self.assertEqual(gmail.labels, {"m0": {"STARRED"}, "m1": set(), "m2": {"UNREAD"}})
        self.assertEqual(self.notices[1][0], " ○ 1 email marked as read")

    def test_star_changes_only_the_chosen_email(self):
        gmail = self.labels_after("star")
        self.assertEqual(gmail.labels, {"m0": {"STARRED"}, "m1": {"UNREAD", "STARRED"}, "m2": {"UNREAD"}})
        self.assertEqual(self.notices[1][0], " ★ 1 email starred")

    def test_open_marks_only_the_opened_email_read(self):
        from unittest import mock
        with mock.patch.object(savegmail, "gmail_url", side_effect=lambda account, msg_id: msg_id) as url:
            gmail = self.labels_after("open")
        self.assertEqual([call.args[1] for call in url.call_args_list], ["m1"])
        self.assertEqual(gmail.labels, {"m0": {"STARRED"}, "m1": set(), "m2": {"UNREAD"}})

    def test_preview_marks_only_the_previewed_email_read(self):
        from unittest import mock
        previewed = []

        def preview(service, user_id, messages, browser, preview_dir):
            previewed.extend(message["id"] for message in messages)
            return [message["id"] for message in messages], {}
        with mock.patch.object(savegmail, "preview_messages", preview):
            gmail = self.labels_after("preview")
        self.assertEqual(previewed, ["m1"])
        self.assertEqual(gmail.labels, {"m0": {"STARRED"}, "m1": set(), "m2": {"UNREAD"}})


class QueryGmail(FakeGmail):
    """FakeGmail whose search applies "(from:bank)" like Gmail, and records the query of every list call."""

    def __init__(self, *args):
        super().__init__(*args)
        self.queries = []

    def message(self, msg_id):
        sender = "bank" if msg_id.startswith("bank") else "other"
        return dict(super().message(msg_id), **{"from": f"S <{sender}@example.com>"})

    def list_candidate_messages(self, service, user_id, query="", max_results=50, page_token=None, in_trash=False):
        self.queries.append(query)
        found, token = super().list_candidate_messages(service, user_id, query, max_results, page_token, in_trash)
        if "(from:bank)" in query.split():
            found = [message for message in found if message["from"] == "S <bank@example.com>"]
        return found, token


class QueryOptionTest(unittest.TestCase):
    """--query is added to every view's search, so a then enter only takes the emails it matches."""

    run_session = UndoAfterDeleteTest.run_session

    def test_query_filters_every_view_and_the_emails_acted_on(self):
        places = {"bank1": "inbox", "o1": "inbox", "bank2": "archive", "o2": "archive", "o3": "inbox"}
        steps = [("download", None)] + [("next_view", [])] * (len(savegmail.VIEWS) - 1)
        gmail, left, offered = self.run_session(places, steps, args=["--query", "from:bank"], gmail_class=QueryGmail)
        self.assertEqual(gmail.places, {"bank1": "trash", "o1": "inbox", "bank2": "trash", "o2": "archive",
                                        "o3": "inbox"})
        self.assertEqual(left, ["bank1-att.bin", "bank1.pdf", "bank2-att.bin", "bank2.pdf"])
        self.assertEqual(gmail.queries, ["(from:bank)"] + [f"(from:bank) {view_filter}"
                                                           for _, view_filter in savegmail.VIEWS[1:]])


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
if [ "$1" = "-m" ] && [ "$2" = "pip" ] && [ "$3" != "--version" ]; then
    exit "${FAKE_PIP_RC:-0}"
fi
exit 0
"""

# A system interpreter: `-m venv --clear <dir>` makes <dir> a working fake .venv.
FAKE_SYSTEM_PYTHON = """#!/bin/sh
printf 'system %s\\n' "$*" >> "$FAKE_LOG"
if [ "$1" = "-c" ]; then
    exit "${FAKE_TOO_OLD:-0}"
fi
if [ "$1" = "-m" ] && [ "$2" = "venv" ] && [ "$3" = "--clear" ]; then
    rm -rf "$4"
    mkdir -p "$4/bin"
    cp "$FAKE_VENV_PYTHON" "$4/bin/python"
    chmod 755 "$4/bin/python"
    exit 0
fi
exit 1
"""

# A .venv built with Python 3.10: pip works, the minimum version check fails.
OLD_VENV_PYTHON = """#!/bin/sh
printf 'old %s\\n' "$*" >> "$FAKE_LOG"
case "$*" in *version_info*) exit 1 ;; esac
exit 0
"""

# A .venv left without pip: every call fails as `No module named pip` would.
BROKEN_VENV_PYTHON = """#!/bin/sh
printf 'broken %s\\n' "$*" >> "$FAKE_LOG"
exit 1
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
        return result.returncode, [call for call in calls if call.startswith("-m pip install")], calls

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


class LauncherVenvTest(unittest.TestCase):
    """run-savegmail.sh finds python3 and rebuilds a .venv that has no pip."""

    TOOLS = ("sh", "dirname", "find", "touch", "rm", "mkdir", "cp", "chmod")

    def setUp(self):
        import shutil
        import tempfile
        if any(shutil.which(tool) is None for tool in self.TOOLS):
            self.skipTest("POSIX tools are required")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = self.tmp.name
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        shutil.copy(os.path.join(repo, "run-savegmail.sh"), root)
        self.bin = os.path.join(root, "bin")
        os.makedirs(self.bin)
        for tool in self.TOOLS:
            os.symlink(shutil.which(tool), os.path.join(self.bin, tool))
        self.venv_python = self.write(os.path.join(root, "venv-python"), FAKE_PYTHON)
        self.system_python = self.write(os.path.join(root, "system-python"), FAKE_SYSTEM_PYTHON)
        self.root = root
        self.log = os.path.join(root, "calls.log")

    @staticmethod
    def write(path, text):
        with open(path, "w") as handle:
            handle.write(text)
        os.chmod(path, 0o755)
        return path

    def provide(self, name):
        os.symlink(self.system_python, os.path.join(self.bin, name))

    def launch(self, **extra):
        import subprocess
        env = {"PATH": self.bin, "FAKE_LOG": self.log, "FAKE_VENV_PYTHON": self.venv_python, **extra}
        result = subprocess.run(["sh", os.path.join(self.root, "run-savegmail.sh"), "--help"],
                                env=env, capture_output=True, text=True, timeout=30)
        calls = []
        if os.path.exists(self.log):
            with open(self.log) as handle:
                calls = handle.read().splitlines()
        return result, calls

    def test_only_python3_creates_venv(self):
        self.provide("python3")
        result, calls = self.launch()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"system -m venv --clear {self.root}/.venv", calls)
        self.assertTrue(calls[-1].endswith("savegmail.py --help"))

    def test_only_python_still_works(self):
        self.provide("python")
        result, calls = self.launch()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(calls[-1].endswith("savegmail.py --help"))

    def test_no_python_or_too_old_says_so(self):
        result, _ = self.launch()
        self.assertEqual(result.returncode, 1)
        self.assertIn("Python 3.11 or newer is required", result.stderr)
        self.provide("python3")
        result, calls = self.launch(FAKE_TOO_OLD="1")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Python 3.11 or newer is required", result.stderr)
        self.assertFalse(any("venv" in call for call in calls))

    def test_venv_without_pip_is_recreated(self):
        self.provide("python3")
        os.makedirs(os.path.join(self.root, ".venv", "bin"))
        self.write(os.path.join(self.root, ".venv", "bin", "python"), BROKEN_VENV_PYTHON)
        result, calls = self.launch()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"system -m venv --clear {self.root}/.venv", calls)
        self.assertTrue(any(call.startswith("-m pip install") for call in calls))
        self.assertTrue(calls[-1].endswith("savegmail.py --help"))

    def test_venv_on_old_python_is_recreated(self):
        self.provide("python3")
        os.makedirs(os.path.join(self.root, ".venv", "bin"))
        self.write(os.path.join(self.root, ".venv", "bin", "python"), OLD_VENV_PYTHON)
        result, calls = self.launch()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"system -m venv --clear {self.root}/.venv", calls)
        self.assertFalse(any(call.startswith("old -m pip install") for call in calls))
        self.assertTrue(calls[-1].endswith("savegmail.py --help"))

    def test_venv_on_old_python_with_old_system_python_says_so(self):
        self.provide("python3")
        os.makedirs(os.path.join(self.root, ".venv", "bin"))
        self.write(os.path.join(self.root, ".venv", "bin", "python"), OLD_VENV_PYTHON)
        result, calls = self.launch(FAKE_TOO_OLD="1")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Python 3.11 or newer is required", result.stderr)
        self.assertFalse(any("venv" in call or "pip install" in call for call in calls))


class AuthenticateTest(unittest.TestCase):
    """Launch sign-in: only a refused refresh asks to sign in again; offline says so and quits."""

    real_sign_in = staticmethod(savegmail.sign_in)

    def setUp(self):
        import io
        import json
        import tempfile
        from unittest import mock
        from rich.console import Console
        tmp = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, tmp, True)
        self.token_path = os.path.join(tmp, "token.json")
        with open(self.token_path, "w") as token:  # expired access token, fake values
            json.dump({"token": "old", "refresh_token": "fake-refresh", "client_id": "id", "client_secret": "secret",
                       "token_uri": "https://oauth2.example.invalid/token", "expiry": "2000-01-01T00:00:00Z"}, token)
        self.output = io.StringIO()
        self.new = mock.Mock()
        self.new.to_json.return_value = json.dumps({"token": "fresh"})
        self.sign_in = mock.Mock(return_value=self.new)
        for patcher in [mock.patch.object(savegmail, "TOKEN_PATH", self.token_path),
                        mock.patch.object(savegmail, "CREDENTIALS_PATH", os.path.join(tmp, "credentials.json")),
                        mock.patch.object(savegmail, "sign_in", self.sign_in),
                        mock.patch.object(savegmail, "console", Console(file=self.output, width=200))]:
            patcher.start()
            self.addCleanup(patcher.stop)

    def refresh_raising(self, error):
        from unittest import mock
        return mock.patch.object(savegmail.Credentials, "refresh", side_effect=error)

    def saved_token(self):
        import json
        with open(self.token_path) as token:
            return json.load(token)

    def test_revoked_token_signs_in_again_and_saves(self):
        with self.refresh_raising(savegmail.RefreshError("invalid_grant: Token has been expired or revoked.")):
            self.assertIs(savegmail.authenticate(), self.new)
        self.assertIn("expired", self.sign_in.call_args[0][0])
        self.assertEqual(self.saved_token(), {"token": "fresh"})

    def test_offline_refresh_says_unreachable_without_sign_in(self):
        with self.refresh_raising(savegmail.TransportError("Failed to resolve 'oauth2.googleapis.com'")):
            with self.assertRaises(SystemExit) as raised:
                savegmail.authenticate()
        self.assertEqual(raised.exception.code, 1)
        self.sign_in.assert_not_called()
        self.assertIn("Gmail unreachable", self.output.getvalue())
        self.assertIn("Failed to resolve", self.output.getvalue())
        self.assertEqual(self.saved_token()["token"], "old")

    def test_offline_profile_at_launch_says_unreachable(self):
        import tempfile
        from unittest import mock
        save_dir = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, save_dir, True)
        service = mock.Mock()
        service.users().getProfile().execute.side_effect = savegmail.httplib2.ServerNotFoundError(
            "Unable to find the server at gmail.googleapis.com")
        with mock.patch.multiple(savegmail, authenticate=lambda: object(), build=lambda *a, **k: service), \
                mock.patch.object(sys, "argv", ["savegmail", "--download-path", save_dir]):
            with self.assertRaises(SystemExit) as raised:
                savegmail.interactive_download_main()
        self.assertEqual(raised.exception.code, 1)
        self.assertIn("Gmail unreachable", self.output.getvalue())

    def test_ctrl_c_while_waiting_for_sign_in_quits_cleanly(self):
        from unittest import mock
        flow = mock.Mock()
        flow.run_local_server.side_effect = KeyboardInterrupt
        with mock.patch.object(savegmail, "oauth_flow", return_value=flow), \
                mock.patch.object(savegmail.webbrowser, "register"):
            with self.assertRaises(SystemExit) as raised:
                try:
                    self.real_sign_in("Sign in to Gmail in your browser.")
                except KeyboardInterrupt:
                    self.fail("Ctrl+C escaped sign_in as a traceback")
        self.assertEqual(raised.exception.code, 1)
        self.assertIn("Sign-in cancelled", self.output.getvalue())


if __name__ == "__main__":
    unittest.main()
