import os
import base64
from playwright.sync_api import sync_playwright
import asyncio
from datetime import datetime
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from tzlocal import get_localzone
from email.utils import parsedate_to_datetime
import subprocess
import sys
import logging
import pytz
import re
import io
import contextlib
import html
from email.parser import BytesParser
from email.policy import default as policy_default
from email.utils import parseaddr
from rich.cells import cell_len
from rich.console import Console
from rich.markup import escape
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn

logging.getLogger('tzlocal').setLevel(logging.ERROR)

console = Console(highlight=False)
VERBOSE = False


def debug(message):
    if VERBOSE:
        console.print(f"[dim]  {escape(message)}[/]")


def warn(message):
    console.print(f"[yellow]![/] {escape(message)}")

def measure_pdf_margins(browser, header_template, footer_template):
    """Measure isolated print templates at A4 width, including wrapped lines."""
    measurement_page = browser.new_page()
    try:
        measurement_page.emulate_media(media="print")
        heights = []
        for template in (header_template, footer_template):
            measurement_page.set_content(
                '<html><head><style>html,body{margin:0;padding:0;}'
                'body{width:210mm;font-family:Arial,sans-serif;}'
                '</style></head><body>' + template + '</body></html>'
            )
            height = measurement_page.evaluate("""async () => {
                await document.fonts.ready;
                // Reserve realistic space for Chromium's injected page numbers.
                document.querySelectorAll('.pageNumber, .totalPages')
                    .forEach(element => element.textContent = '9999');
                return Math.ceil(document.body.firstElementChild
                    .getBoundingClientRect().height);
            }""")
            # Chromium's header/footer edge padding (20px) plus an 8px body gap.
            heights.append(height + 28)
        if sum(heights) >= 297 / 25.4 * 96:
            raise ValueError("Email header and footer exceed the height of an A4 page")
        return {"top": f"{heights[0]}px", "bottom": f"{heights[1]}px",
                "left": "0", "right": "0"}
    finally:
        measurement_page.close()


def launch_browser(playwright, headed=False):
    """Launch full Chromium (new headless mode unless headed), installing it if missing."""
    def launch():
        return playwright.chromium.launch(channel="chromium", headless=not headed)

    try:
        return launch()
    except Exception as error:
        warn(f"Playwright Chromium is not ready: {error}")
        console.print("[dim]Installing Chromium for Playwright…[/]")
        subprocess.run([sys.executable, "-m", "playwright", "install", "chromium"], check=True)
        return launch()

SCOPES = ["https://mail.google.com/"]
# SCOPES = ["https://www.googleapis.com/auth/gmail.readonly", "https://www.googleapis.com/auth/gmail.modify"]
DOWNLOAD_PATH = '~/GMail/'
# OAuth files live next to the script, wherever it is launched from.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TOKEN_PATH = os.path.join(SCRIPT_DIR, "token.json")
CREDENTIALS_PATH = os.path.join(SCRIPT_DIR, "credentials.json")

def get_real_date(date_string):
    if date_string == 'No Date':
        return date_string
    try:
        parsed_date = datetime.strptime(date_string, '%Y.%m.%d-%H.%M.%S')
    except ValueError:
        try:
            parsed_date = parsedate_to_datetime(date_string)
        except ValueError:
            parsed_date = None
    if parsed_date:
        local_tz = get_localzone()
        local_date = parsed_date.astimezone(local_tz)
        formatted_date = local_date.strftime("%Y-%m-%d %H:%M:%S %Z")
        return formatted_date
    else:
        return 'Invalid Date'


def convert_expiry_to_local_time(expiry_utc):
    local_timezone = get_localzone()
    utc_timezone = pytz.utc
    expiry_utc = utc_timezone.localize(expiry_utc)
    expiry_local = expiry_utc.astimezone(local_timezone)
    return expiry_local


def oauth_flow():
    if not os.path.exists(CREDENTIALS_PATH):
        console.print(
            f"[red]✗[/] Missing Google OAuth client file: {escape(CREDENTIALS_PATH)}\n"
            "  [dim]Download it from Google Cloud Console → APIs & Services → Credentials "
            "(OAuth client ID, Desktop app) and save it there as credentials.json.[/]"
        )
        sys.exit(1)
    return InstalledAppFlow.from_client_secrets_file(CREDENTIALS_PATH, SCOPES)


def authenticate():
    creds = None
    if os.path.exists(TOKEN_PATH):
        creds = Credentials.from_authorized_user_file(TOKEN_PATH, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                debug(f"Token refreshed, expires {convert_expiry_to_local_time(creds.expiry)}")
            except Exception as e:
                warn(f"Could not refresh token: {e}")
                flow = oauth_flow()
                creds = flow.run_local_server(port=0)
                debug(f"Token expires {convert_expiry_to_local_time(creds.expiry)}")
        else:
            flow = oauth_flow()
            creds = flow.run_local_server(port=0)
            debug(f"Token expires {convert_expiry_to_local_time(creds.expiry)}")
        with open(TOKEN_PATH, "w") as token:
            token.write(creds.to_json())
    return creds

def truncate_bytes(text, limit):
    """Cut text to at most limit UTF-8 bytes without splitting a character."""
    return text.encode("utf-8")[:limit].decode("utf-8", "ignore")


def remove_files(paths):
    for path in paths:
        with contextlib.suppress(FileNotFoundError):
            os.remove(path)


def save_email_and_attachments(service, user_id, msg_id, save_dir, browser, on_step=lambda step: None):
    """Save one email as PDF + attachments; on failure, remove what was written so a retry starts clean."""
    written = []
    try:
        return write_email_files(service, user_id, msg_id, save_dir, browser, on_step, written)
    except Exception:
        remove_files(written)
        raise


def write_email_files(service, user_id, msg_id, save_dir, browser, on_step, written):
    def sanitize_subject_for_filename(subject):
        safe = (subject or "")
        safe = (safe
            .replace("/", "-")
            .replace("\\", "-")
            .replace(":", "-")
            .replace("*", "-")
            .replace("+", "-")
            .replace("é", "e")
            .replace("à", "a"))
        # Linux caps file names at 255 bytes; leave room for the timestamp prefix and ".pdf".
        safe = truncate_bytes(safe.strip(), 150).rstrip(". ")
        return safe or "No_Subject"

    on_step("fetching")
    message = service.users().messages().get(userId=user_id, id=msg_id, format='raw').execute()
    raw = message['raw']
    email_bytes = base64.urlsafe_b64decode(raw)
    msg = BytesParser(policy=policy_default).parse(io.BytesIO(email_bytes))

    # Extract headers
    subject = msg['Subject'] or ""
    file_safe_subject = sanitize_subject_for_filename(subject)
    fro = msg['From'] or ""
    if '<' in fro and '>' in fro:
        fro_name, fro_email = fro.split('<', 1)
        fro_email = fro_email.rstrip('>')
        fro_email = f" {fro_email}"
        fro = f"{fro_name.strip()} {fro_email.strip()} "
    reply = msg['Reply-To'] or ""
    if '<' in reply and '>' in reply:
        reply_name, reply_email = reply.split('<', 1)
        reply_email = reply_email.rstrip('>')
        reply_email = f" {reply_email}"
        reply = f"{reply_name.strip()} {reply_email.strip()} "
    to = msg['To'] or ""
    if '<' in to and '>' in to:
        # First split all recipients by comma
        recipients = [r.strip() for r in to.split(',')]

        formatted = []
        for recipient in recipients:
            if '<' in recipient and '>' in recipient:
                to_name, to_email = recipient.split('<', 1)
                to_email = to_email.rstrip('>')
                to_email = f" {to_email}"
                formatted.append(f"{to_name.strip()} {to_email.strip()} ")
            else:
                formatted.append(recipient)

        # Rebuild the full string
        to = ", ".join(formatted)
    cc = msg['Cc'] or ""
    if cc:
        cc_list = []
        for email in cc.split(','):
            email = email.strip()
            if '<' in email and '>' in email:
                cc_name, cc_email = email.split('<', 1)
                cc_email = cc_email.rstrip('>')
                cc_email = f" {cc_email}"
                cc_list.append(f"{cc_name.strip()} {cc_email.strip()}")
            else:
                cc_list.append(email.strip())
        cc = ', '.join(cc_list)
    date = get_real_date(msg['Date'] or 'No Date')

    # Extract HTML or plain text
    html_part = msg.get_body(preferencelist=('html',))
    if html_part:
        debug("Email body selected: HTML")
        html_content = html_part.get_content()
    else:
        plain_part = msg.get_body(preferencelist=('plain',))
        if plain_part:
            debug("Email body selected: plain text")
            plain_text = plain_part.get_content()
            plain_text = re.sub(r'(>>?|>)', r'\1', plain_text)
            plain_text = re.sub(r'(On \d{2}/\d{2}/\d{4})', r'\n\n\1', plain_text)
            date_regex = r'((Le|The) \d{1,2} (janv\.|févr\.|mars\.|avr\.|mai\.|juin\.|juil\.|août\.|sept\.|oct\.|nov\.|déc\.|Jan\.|Feb\.|Mar\.|Apr\.|May\.|Jun\.|Jul\.|Aug\.|Sep\.|Oct\.|Nov\.|Dec\.) \d{4}( (à|at) \d{1,2}:\d{2})?)'
            plain_text = re.sub(date_regex, r'\n\n\1', plain_text)
            url_regex = r'(https?://[^\s<>"]+|www\.[^\s<>"]+)'
            plain_text = re.sub(url_regex, r'<a href="\1" target="_blank">\1</a>', plain_text)
            html_content = plain_text.replace('\n', '<br>')
            html_content = f"""
            <html>
            <body>
                <div style="font-family: Arial, sans-serif;font-size: 10px">
                    {html_content}
                </div>
            </body>
            </html>
            """
        else:
            warn("No HTML or plain text body found in email.")
            html_content = "No content found in email."

    # Extract attachments and inline images
    attachments_files = []
    cid_map = {}
    counter = 0  # Counter for generated Content-IDs
    used_filenames = set()

    def clean_filename(filename):
        if not filename:
            return None
        filename = re.sub(r'[<>:\"/\\|?*]', '_', filename).strip()
        base, ext = os.path.splitext(filename)
        base, ext = truncate_bytes(base, 180), truncate_bytes(ext, 20)
        filename = base + ext
        counter = 1
        candidate = filename

        while (os.path.exists(os.path.join(save_dir, candidate)) or 
               candidate in used_filenames):
            candidate = f"{base}({counter}){ext}"
            counter += 1

        used_filenames.add(candidate)
        return candidate

    for part in msg.walk():
        debug(f"Part: Content-Type={part.get_content_type()}, Content-ID={part.get('Content-ID')}, Filename={part.get_filename()}, Disposition={part.get_content_disposition()}")
        if part.get_content_maintype() == 'multipart':
            continue
        original_filename = part.get_filename()
        filename = clean_filename(original_filename) if original_filename else None
        content_type = part.get_content_type()
        content_id = part.get('Content-ID')
        content_disposition = part.get_content_disposition()  # New: Get disposition

        # Handle true attachments: Save if filename and disposition is 'attachment' (or no CID for safety)
        if filename and (content_disposition == 'attachment' or not content_id):
            payload = part.get_payload(decode=True)
            path = os.path.join(save_dir, filename)
            written.append(path)
            with open(path, 'wb') as f:
                f.write(payload)
            attachments_files.append(filename)
            debug(f"Attachment saved: {filename}")

        # Handle images (inline or otherwise): Always embed if image and has CID
        if content_type.startswith('image/'):
            payload = part.get_payload(decode=True)
            base64_data = base64.b64encode(payload).decode('utf-8')
            data_url = f"data:{content_type};base64,{base64_data}"
            if content_id:
                content_id = content_id.strip('<>')
                cid_map[content_id] = data_url
                debug(f"Mapped CID {content_id} to data URL: {data_url[:50]}...")
            elif not filename:  # Generate CID only for true inline without filename
                generated_cid = f"generated_cid_{counter}"
                cid_map[generated_cid] = data_url
                debug(f"Generated CID {generated_cid} for inline image without Content-ID: {data_url[:50]}...")
                counter += 1

    # Replace cid: in HTML with data: URLs
    def replace_cid(match):
        cid_value = match.group(1)
        if cid_value in cid_map:
            debug(f"Replacing CID: {cid_value} with data URL: {cid_map[cid_value][:50]}...")
            return f'src="{cid_map[cid_value]}"'
        debug(f"No mapping found for CID: {cid_value}")
        return match.group(0)

    html_content = re.sub(r'src=["\']cid:([^"\']+)["\']', replace_cid, html_content)

    # Handle external URLs (keep intact)
    # The regex already skips them since it looks for cid:

    # Generate attachments_html
    if attachments_files:
        attachments_html_footer = "<div>Attachments:</div>\n<ul style='list-style-type: none; padding: 0; margin: 0;'>\n"
        for attachment in attachments_files:
            attachment_path = os.path.join(save_dir, attachment)
            attachment_url = f"file://{os.path.abspath(attachment_path)}"
            attachments_html_footer += f"  <li style='margin-bottom: 0;'><h6 style='margin: 0; padding: 0;'><a href='{attachment_url}'>{attachment}</a></h6></li>\n"
        attachments_html_footer += "</ul>\n"
    else:
        attachments_html_footer = "<div>No attachments for this mail</div>"

    # Generate PDF
    final_pdf_path = os.path.join(save_dir, f"{file_safe_subject}.pdf")
    written.append(final_pdf_path)

    on_step("rendering PDF")
    page = browser.new_page()
    try:
        page.set_content(html_content, timeout=120000, wait_until="networkidle")
        # Emails often defer images; force them in and wait for fonts/images before printing.
        page.evaluate("""async () => {
            document.querySelectorAll('img[data-src]').forEach(img => {
                if (!img.getAttribute('src')) img.src = img.dataset.src;
            });
            document.querySelectorAll('img[loading="lazy"]').forEach(img => img.loading = 'eager');
            const pending = [...document.images].filter(img => !img.complete)
                .map(img => new Promise(resolve => { img.onload = img.onerror = resolve; }));
            const timeout = new Promise(resolve => setTimeout(resolve, 15000));
            await Promise.race([Promise.all([document.fonts.ready, ...pending]), timeout]);
        }""")
        page.wait_for_timeout(300)

        header_template = """
            <div style="font-family: Arial, sans-serif; font-size: 10px; line-height: normal; color: #666; text-align: center; width: 100%; box-sizing: border-box; padding: 0 12px; overflow-wrap: anywhere; display: flow-root">
                <h3 style='margin-top: 0px;'>{subject}</h3>
                <div>From : {fro}</div>
                <div>Reply To : {reply}</div>
                <div>To : {to}</div>
                <div>Cc : {cc}</div>
                <div>Date : {date}</div>
            </div>
        """.format(fro=fro, reply=reply, to=to, cc=cc, date=date, subject=subject)
        footer_template = f"""
            <div style="font-family: Arial, sans-serif; font-size: 10px; line-height: normal; color: #666; text-align: center; width: 100%; box-sizing: border-box; padding: 0 12px; overflow-wrap: anywhere; display: flow-root">
                {attachments_html_footer}
                <div style="margin-top: 8px;"><a href='https://mail.google.com/mail/u/0/#inbox/{msg_id}'>View in Gmail</a></div>
                <span class="pageNumber"></span> / <span class="totalPages"></span>
            </div>
        """

        pdf_margins = measure_pdf_margins(browser, header_template, footer_template)

        page.pdf(
            format='A4',
            print_background=True,
            display_header_footer=True,
            header_template=header_template,
            footer_template=footer_template,
            margin=pdf_margins,
            path=final_pdf_path
        )
    except Exception as e:
        raise RuntimeError(f"PDF generation failed: {e}") from e
    finally:
        page.close()

    now = datetime.now()
    timestamp = now.strftime("%y%m%d_%H%M%S")
    milliseconds = now.microsecond // 1000
    new_pdf_path = os.path.join(save_dir, f"{timestamp}{milliseconds}_{file_safe_subject}.pdf")
    os.rename(final_pdf_path, new_pdf_path)
    written[-1] = new_pdf_path
    debug(f"Saved {os.path.basename(new_pdf_path)}")
    return {"pdf": os.path.basename(new_pdf_path), "attachments": len(attachments_files), "files": written}

def empty_trash(service):
    """
    Permanently deletes all messages from the trash, after confirmation.
    """
    try:
        ids = []
        with console.status("[dim]Listing trash…[/]"):
            request = service.users().messages().list(userId='me', labelIds=['TRASH'], maxResults=500)
            while request is not None:
                results = request.execute()
                ids.extend(message['id'] for message in results.get('messages', []))
                request = service.users().messages().list_next(request, results)

        if not ids:
            console.print("[dim]The trash is already empty.[/]")
            return

        answer = console.input(f"Permanently delete [bold]{len(ids)}[/] message(s) from trash? [dim]\\[y/N][/] ")
        if answer.strip().lower() not in {"y", "yes", "o", "oui"}:
            console.print("[dim]Cancelled.[/]")
            return

        with console.status("[dim]Deleting…[/]"):
            for start in range(0, len(ids), 1000):
                service.users().messages().batchDelete(userId='me', body={"ids": ids[start:start + 1000]}).execute()

        console.print(f"[green]✓[/] {len(ids)} message(s) permanently deleted from trash.")

    except Exception as e:
        console.print(f"[red]✗[/] Error while emptying trash: {escape(str(e))}")


def move_message_to_trash(service, user_id, msg_id):
    """Move a Gmail message to trash after a successful local save."""
    service.users().messages().trash(userId=user_id, id=msg_id).execute()
    debug(f"Message moved to Gmail trash: {msg_id}")



def extract_header(headers, name, default=""):
    for header in headers or []:
        if header.get("name", "").lower() == name.lower():
            return header.get("value", default)
    return default


METADATA_FIELDS = "id,threadId,internalDate,payload/headers,snippet"
METADATA_BATCH_SIZE = 50  # Gmail throttles larger batches


def metadata_request(service, user_id, msg_id):
    return service.users().messages().get(
        userId=user_id,
        id=msg_id,
        format="metadata",
        metadataHeaders=["Subject", "From", "Date"],
        fields=METADATA_FIELDS,
    )


def to_candidate(detail):
    headers = detail.get("payload", {}).get("headers", [])
    return {
        "id": detail["id"],
        "threadId": detail.get("threadId", ""),
        "internalDate": int(detail.get("internalDate", 0)),
        "date": get_real_date(extract_header(headers, "Date", "No Date")),
        "from": extract_header(headers, "From", ""),
        "subject": extract_header(headers, "Subject", "No Subject"),
        "snippet": detail.get("snippet", ""),
    }


def list_candidate_messages(service, user_id, query="", max_results=50, page_token=None):
    """Return (messages sorted oldest first, token for the next older page or None).

    Empty query means: list all visible Gmail messages, letting the user choose
    which ones to download afterwards.
    """
    ids = []
    while len(ids) < max_results:
        response = service.users().messages().list(
            userId=user_id,
            q=query,
            maxResults=min(max_results - len(ids), 500),
            pageToken=page_token,
        ).execute()
        ids.extend(message["id"] for message in response.get("messages", []))
        page_token = response.get("nextPageToken")
        if not page_token:
            break

    details = {}
    failed = []

    def collect(request_id, response, exception):
        if exception is None:
            details[request_id] = response
        else:
            failed.append(request_id)

    for start in range(0, len(ids), METADATA_BATCH_SIZE):
        batch = service.new_batch_http_request(callback=collect)
        for msg_id in ids[start:start + METADATA_BATCH_SIZE]:
            batch.add(metadata_request(service, user_id, msg_id), request_id=msg_id)
        batch.execute()

    # Retry throttled/failed batch entries one by one.
    for msg_id in failed:
        try:
            details[msg_id] = metadata_request(service, user_id, msg_id).execute()
        except Exception as exc:
            debug(f"Could not read metadata for message {msg_id}: {exc}")

    detailed_messages = [to_candidate(details[msg_id]) for msg_id in ids if msg_id in details]
    detailed_messages.sort(key=lambda item: item["internalDate"])
    return detailed_messages, page_token


def fit(value, width):
    """Collapse whitespace, then truncate/pad to a visible terminal width."""
    value = re.sub(r"\s+", " ", value or "").strip()
    if width <= 0:
        return ""
    if cell_len(value) <= width:
        return value + " " * (width - cell_len(value))
    kept, used = [], 0
    for char in value:
        char_width = cell_len(char)
        if used + char_width > width - 1:
            break
        kept.append(char)
        used += char_width
    return "".join(kept) + "…" + " " * (width - 1 - used)


def sender_name(sender):
    name, address = parseaddr(sender or "")
    return name.strip().strip('"') or address or "—"


def compact_date(internal_date_ms):
    """Mail-client style date: time today, day+month this year, ISO date otherwise."""
    if not internal_date_ms:
        return "—"
    local_date = datetime.fromtimestamp(internal_date_ms / 1000, get_localzone())
    now = datetime.now(local_date.tzinfo)
    if local_date.date() == now.date():
        return local_date.strftime("%H:%M")
    if local_date.year == now.year:
        return f"{local_date.day} {local_date.strftime('%b')}"
    return local_date.strftime("%Y-%m-%d")


def message_row(message):
    subject = message.get("subject") or "No Subject"
    sender = sender_name(message.get("from"))
    snippet = html.unescape(message.get("snippet") or "")
    return {
        "date": compact_date(message.get("internalDate")),
        "sender": sender,
        "subject": subject,
        "snippet": snippet,
        "haystack": f"{sender} {message.get('from', '')} {subject}".lower(),
    }


def column_widths(rows, total_width):
    """Return (sender, subject, snippet) widths for the space left after fixed columns."""
    fixed = 4 + 10 + 2  # cursor + checkbox, date, gap
    sender_w = min(max((cell_len(row["sender"]) for row in rows), default=6), 22)
    rest = max(0, total_width - fixed - sender_w - 2 - 1)
    longest_subject = max((cell_len(row["subject"]) for row in rows), default=7)
    subject_w = min(longest_subject, max(20, int(rest * 0.6)), rest)
    snippet_w = rest - subject_w - 2
    return sender_w, subject_w, snippet_w if snippet_w >= 10 else 0


def pick_messages(messages, load_more=None):
    """Interactive multi-select list. Returns selected messages, [] on quit.

    load_more() returns (older messages sorted oldest first, whether even older ones remain).
    """
    from prompt_toolkit.application import Application, get_app
    from prompt_toolkit.filters import Condition
    from prompt_toolkit.key_binding import KeyBindings
    from prompt_toolkit.layout import HSplit, Layout, Window
    from prompt_toolkit.layout.controls import FormattedTextControl
    from prompt_toolkit.layout.dimension import Dimension
    from prompt_toolkit.styles import Style

    messages = list(messages)
    rows = [message_row(message) for message in messages]
    state = {"cursor": 0, "top": 0, "query": "", "filtering": False, "selected": set(),
             "loading": False, "exhausted": load_more is None}

    def visible():
        terms = state["query"].lower().split()
        return [i for i, row in enumerate(rows) if all(term in row["haystack"] for term in terms)]

    def size():
        return get_app().output.get_size()

    def list_height():
        # Leave room for the startup line above the picker and its own header/footer.
        return max(1, min(len(rows), size().rows - 6))

    def clamp():
        indexes = visible()
        state["cursor"] = max(0, min(state["cursor"], len(indexes) - 1))
        height = list_height()
        if state["cursor"] < state["top"]:
            state["top"] = state["cursor"]
        elif state["cursor"] >= state["top"] + height:
            state["top"] = state["cursor"] - height + 1
        state["top"] = max(0, min(state["top"], max(0, len(indexes) - height)))
        return indexes

    def render_header():
        indexes = visible()
        parts = [("class:title", " Gmail"), ("class:dim", f" · {len(rows)} emails · oldest → newest")]
        if state["query"]:
            parts.append(("class:dim", f" · {len(indexes)} match "))
            parts.append(("class:accent", state["query"]))
        return parts

    def render_list():
        indexes = clamp()
        if not indexes:
            return [("class:dim", "   No email matches this filter.")]
        sender_w, subject_w, snippet_w = column_widths(rows, size().columns)
        lines = []
        for position in range(state["top"], min(len(indexes), state["top"] + list_height())):
            index = indexes[position]
            row = rows[index]
            current = position == state["cursor"]
            checked = messages[index]["id"] in state["selected"]
            if lines:
                lines.append(("", "\n"))
            lines += [
                ("class:cursor", " ❯ " if current else "   "),
                ("class:checked" if checked else "class:dim", "● " if checked else "○ "),
                ("class:dim", fit(row["date"], 10) + "  "),
                ("class:sender", fit(row["sender"], sender_w) + "  "),
                ("class:subject.current" if current else "", fit(row["subject"], subject_w)),
            ]
            if snippet_w:
                lines.append(("class:dim", "  " + fit(row["snippet"], snippet_w)))
        return lines

    def render_footer():
        count = len(state["selected"])
        if state["filtering"]:
            hint = [("class:accent", " / "), ("", state["query"]), ("class:accent", "▏"),
                    ("class:dim", "   enter apply · esc clear")]
        else:
            hint = []
            keys = [("↑↓", "move"), ("space", "select"), ("a", "all"), ("/", "filter")]
            if not state["exhausted"]:
                keys.append(("m", "loading…" if state["loading"] else "more"))
            for key, label in keys + [("enter", "download"), ("q", "quit")]:
                hint += [("class:dim", " · " if hint else " "), ("class:key", key), ("class:dim", f" {label}")]
        status = f"{count} selected " if count else ""
        used = sum(cell_len(text) for _, text in hint)
        gap = max(2, size().columns - used - cell_len(status) - 1)
        return hint + [("", " " * gap), ("class:checked", status)]

    filtering = Condition(lambda: state["filtering"])
    browsing = ~filtering
    bindings = KeyBindings()

    def move(delta):
        state["cursor"] += delta
        clamp()

    bindings.add("up")(lambda event: move(-1))
    bindings.add("down")(lambda event: move(1))
    bindings.add("pageup")(lambda event: move(-list_height()))
    bindings.add("pagedown")(lambda event: move(list_height()))
    bindings.add("k", filter=browsing)(lambda event: move(-1))
    bindings.add("j", filter=browsing)(lambda event: move(1))
    bindings.add("home", filter=browsing)(lambda event: move(-len(rows)))
    bindings.add("end", filter=browsing)(lambda event: move(len(rows)))

    @bindings.add("space", filter=browsing)
    def _(event):
        indexes = visible()
        if indexes:
            state["selected"] ^= {messages[indexes[state["cursor"]]]["id"]}
            move(1)

    @bindings.add("a", filter=browsing)
    def _(event):
        ids = {messages[index]["id"] for index in visible()}
        if ids <= state["selected"]:
            state["selected"] -= ids
        else:
            state["selected"] |= ids

    @bindings.add("/", filter=browsing)
    def _(event):
        state["filtering"] = True

    @bindings.add("enter", filter=browsing)
    def _(event):
        indexes = visible()
        if not state["selected"] and indexes:
            state["selected"].add(messages[indexes[state["cursor"]]]["id"])
        if state["selected"]:
            event.app.exit(result=[message for message in messages if message["id"] in state["selected"]])

    @bindings.add("m", filter=browsing)
    def _(event):
        if state["loading"] or state["exhausted"]:
            return
        state["loading"] = True

        async def load():
            older, more = await asyncio.to_thread(load_more)
            state["exhausted"] = not more
            # Older emails go on top; keep the cursor on the same email.
            current_id = None
            indexes = visible()
            if indexes:
                current_id = messages[indexes[state["cursor"]]]["id"]
            messages[:0] = older
            rows[:0] = [message_row(message) for message in older]
            if current_id:
                state["cursor"] = next(
                    position for position, index in enumerate(visible()) if messages[index]["id"] == current_id
                )
            state["loading"] = False
            event.app.invalidate()

        event.app.create_background_task(load())

    @bindings.add("q", filter=browsing)
    @bindings.add("escape", filter=browsing)
    @bindings.add("c-c")
    def _(event):
        event.app.exit(result=[])

    @bindings.add("enter", filter=filtering)
    def _(event):
        state["filtering"] = False

    @bindings.add("escape", filter=filtering)
    def _(event):
        state["filtering"] = False
        state["query"] = ""

    @bindings.add("backspace", filter=filtering)
    def _(event):
        state["query"] = state["query"][:-1]
        state["cursor"] = 0

    @bindings.add("<any>", filter=filtering)
    def _(event):
        if event.data.isprintable():
            state["query"] += event.data
            state["cursor"] = 0

    style = Style.from_dict({
        "title": "bold",
        "dim": "fg:ansibrightblack",
        "accent": "fg:ansicyan bold",
        "cursor": "fg:ansicyan bold",
        "checked": "fg:ansigreen bold",
        "sender": "fg:ansicyan",
        "subject.current": "bold",
        "key": "bold",
    })
    layout = Layout(HSplit([
        Window(FormattedTextControl(render_header), height=1),
        Window(height=1),
        Window(FormattedTextControl(render_list), height=lambda: Dimension.exact(list_height())),
        Window(height=1),
        Window(FormattedTextControl(render_footer), height=1),
    ]))
    app = Application(layout=layout, key_bindings=bindings, style=style, erase_when_done=True)
    app.ttimeoutlen = 0.05
    return app.run() or []


def print_message_line(mark, message, detail="", sender_w=22):
    row = message_row(message)
    width = console.width
    detail_w = max(20, cell_len(detail))
    subject_w = max(10, width - 4 - 12 - sender_w - 2 - detail_w - 3)
    console.print(
        f" {mark}  [dim]{escape(fit(row['date'], 10))}[/]  "
        f"[cyan]{escape(fit(row['sender'], sender_w))}[/]  "
        f"{escape(fit(row['subject'], subject_w))}  [dim]{escape(fit(detail, width - 4 - 12 - sender_w - 2 - subject_w - 3))}[/]"
    )


def parse_selection(selection, total):
    selection = (selection or "").strip().lower()
    if selection in {"q", "quit", "exit"}:
        return []
    if selection in {"a", "all", "tous", "tout"}:
        return list(range(total))

    selected = set()
    for part in re.split(r"[,\s]+", selection):
        if not part:
            continue
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            try:
                start = int(start_text)
                end = int(end_text)
            except ValueError:
                raise ValueError(f"Invalid selection: {part}")
            if start > end:
                start, end = end, start
            for number in range(start, end + 1):
                if 1 <= number <= total:
                    selected.add(number - 1)
                else:
                    raise ValueError(f"Number out of range: {number}")
        else:
            try:
                number = int(part)
            except ValueError:
                raise ValueError(f"Invalid selection: {part}")
            if 1 <= number <= total:
                selected.add(number - 1)
            else:
                raise ValueError(f"Number out of range: {number}")
    return sorted(selected)


def ask_user_to_select_messages(messages, load_more=None):
    """Pick emails interactively, or by typed numbers when not attached to a terminal."""
    if not messages:
        return []
    if sys.stdin.isatty() and sys.stdout.isatty():
        return pick_messages(messages, load_more)

    sender_w = min(max(cell_len(sender_name(m.get("from"))) for m in messages), 22)
    num_w = len(str(len(messages)))
    for number, message in enumerate(messages, start=1):
        row = message_row(message)
        subject_w = max(10, console.width - num_w - 18 - sender_w)
        console.print(escape(f" {number:>{num_w}}  {fit(row['date'], 10)}  {fit(row['sender'], sender_w)}  {fit(row['subject'], subject_w)}"))
    while True:
        try:
            answer = input("\nSelect (e.g. 1,3 · 2-6 · all · q) > ")
        except EOFError:
            return []
        try:
            return [messages[index] for index in parse_selection(answer, len(messages))]
        except ValueError as exc:
            warn(f"{exc}. Try again.")


def interactive_download_main():
    import argparse

    parser = argparse.ArgumentParser(
        description=(
            "List available Gmail messages, let the user choose which ones to download as PDFs, "
            "then move processed emails to the Gmail trash."
        )
    )
    parser.add_argument(
        "--query",
        default="",
        help="Optional Gmail search query used to filter the list (default: none, so all emails). Examples: 'newer_than:30d', 'from:foo', or 'has:attachment'.",
    )
    parser.add_argument(
        "--max",
        type=int,
        default=50,
        help="Maximum number of emails to list (default: 50).",
    )
    parser.add_argument(
        "--download-path",
        metavar="PATH",
        default=DOWNLOAD_PATH,
        help="Download directory (default: %(default)s).",
    )
    parser.add_argument(
        "--trash",
        action="store_true",
        help="Empty the Gmail trash only. Manual option, not run automatically after downloads.",
    )
    parser.add_argument(
        "--headed",
        action="store_true",
        help="Render PDFs in a visible Chromium window (fallback if an email captures badly headless).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show token, Chromium, MIME and PDF rendering details.",
    )
    args = parser.parse_args()
    global VERBOSE
    VERBOSE = args.verbose

    if args.trash:
        creds = authenticate()
        service = build("gmail", "v1", credentials=creds)
        empty_trash(service)
        return

    console.clear()
    creds = authenticate()
    try:
        service = build("gmail", "v1", credentials=creds)
        user_id = "me"
        save_dir = os.path.expanduser(args.download_path)
        os.makedirs(save_dir, exist_ok=True)
        shown_dir = save_dir.replace(os.path.expanduser("~"), "~", 1)

        account = service.users().getProfile(userId=user_id).execute().get("emailAddress", user_id)
        console.print(
            f" [bold]savegmail[/]  [dim]·[/]  {escape(account)}  [dim]·  query:[/] "
            f"{escape(args.query) if args.query else '[dim](all)[/]'}  [dim]·  →[/] {escape(shown_dir)}\n"
        )
        with console.status("[dim]Fetching emails…[/]"):
            messages, next_page = list_candidate_messages(service, user_id, query=args.query, max_results=args.max)

        if not messages:
            console.print("[dim]No emails found for this query.[/]")
            return

        def load_more():
            nonlocal next_page
            older, next_page = list_candidate_messages(
                service, user_id, query=args.query, max_results=args.max, page_token=next_page
            )
            return older, next_page is not None

        selected_messages = ask_user_to_select_messages(messages, load_more if next_page else None)
        if not selected_messages:
            console.print("[dim]No email selected.[/]")
            return

        playwright = sync_playwright().start()
        with console.status("[dim]Preparing Chromium…[/]"):
            browser = launch_browser(playwright, headed=args.headed)

        sender_w = min(max(cell_len(sender_name(m.get("from"))) for m in selected_messages), 22)
        saved, attachments, failed = 0, 0, 0
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[dim]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            console=console,
            transient=True,
        )
        try:
            with progress:
                task = progress.add_task("", total=len(selected_messages))
                for message in selected_messages:
                    subject = fit(message.get("subject") or "No Subject", 40).rstrip()

                    def on_step(step):
                        progress.update(task, description=escape(f"{subject} · {step}…"))

                    try:
                        result = save_email_and_attachments(
                            service, user_id, message["id"], save_dir, browser, on_step
                        )
                        on_step("moving to trash")
                        try:
                            move_message_to_trash(service, user_id, message["id"])
                        except Exception:
                            # Email stays in Gmail, so drop its files to keep a retry duplicate-free.
                            remove_files(result["files"])
                            raise
                    except Exception as exc:
                        failed += 1
                        print_message_line("[red]✗[/]", message, "failed", sender_w)
                        console.print(f"      [dim]└ {escape(str(exc))}[/]")
                    else:
                        saved += 1
                        attachments += result["attachments"]
                        count = result["attachments"]
                        detail = f"PDF + {count} attachment{'s' * (count > 1)}" if count else "PDF"
                        print_message_line("[green]✓[/]", message, detail, sender_w)
                    progress.advance(task)
        finally:
            browser.close()
            playwright.stop()

        summary = f"{saved} email{'s' * (saved != 1)} · {saved} PDF{'s' * (saved != 1)}"
        summary += f" · {attachments} attachment{'s' * (attachments != 1)} · moved to trash"
        if failed:
            summary += f" · [red]{failed} failed[/] (kept in Gmail)"
        console.print(f"\n [bold]Done[/] [dim]·[/] {summary}\n [dim]→[/] {escape(shown_dir)}")

    except HttpError as error:
        console.print(f"[red]✗[/] Gmail API error: {escape(str(error))}")

if __name__ == "__main__":
    interactive_download_main()
