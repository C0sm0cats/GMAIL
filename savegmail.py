import os
import base64
from playwright.sync_api import sync_playwright
import asyncio
from datetime import datetime, timezone
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
    expiry_utc = expiry_utc.replace(tzinfo=timezone.utc)
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
            delete_messages(service, 'me', ids)

        console.print(f"[green]✓[/] {len(ids)} message(s) permanently deleted from trash.")

    except Exception as e:
        console.print(f"[red]✗[/] Error while emptying trash: {escape(str(e))}")


API_BATCH_SIZE = 50  # Gmail throttles larger batches


def run_batched(service, ids, make_request):
    """Run make_request(id) for every id in Gmail batch calls, retrying failed entries one by one.

    Returns ({id: response}, {id: exception}).
    """
    responses, errors = {}, {}

    def collect(request_id, response, exception):
        if exception is None:
            responses[request_id] = response
        else:
            errors[request_id] = exception

    for start in range(0, len(ids), API_BATCH_SIZE):
        batch = service.new_batch_http_request(callback=collect)
        for msg_id in ids[start:start + API_BATCH_SIZE]:
            batch.add(make_request(msg_id), request_id=msg_id)
        batch.execute()

    # Retry throttled/failed batch entries one by one.
    for msg_id in list(errors):
        try:
            responses[msg_id] = make_request(msg_id).execute()
            del errors[msg_id]
        except Exception as exc:
            errors[msg_id] = exc
            debug(f"Gmail request failed for message {msg_id}: {exc}")
    return responses, errors


def delete_messages(service, user_id, ids):
    """Permanently delete messages, bypassing the trash. Cannot be undone."""
    for start in range(0, len(ids), 1000):
        service.users().messages().batchDelete(userId=user_id, body={"ids": ids[start:start + 1000]}).execute()


def trash_messages(service, user_id, ids):
    """Move messages to the Gmail trash. Returns {id: exception} for the ones that failed."""
    _, errors = run_batched(service, ids, lambda msg_id: service.users().messages().trash(userId=user_id, id=msg_id))
    return errors


def untrash_messages(service, user_id, ids):
    """Restore messages from the Gmail trash. Returns {id: exception} for the ones that failed."""
    _, errors = run_batched(service, ids, lambda msg_id: service.users().messages().untrash(userId=user_id, id=msg_id))
    return errors



def extract_header(headers, name, default=""):
    for header in headers or []:
        if header.get("name", "").lower() == name.lower():
            return header.get("value", default)
    return default


METADATA_FIELDS = "id,threadId,internalDate,payload(mimeType,headers),snippet"


def metadata_request(service, user_id, msg_id):
    return service.users().messages().get(
        userId=user_id,
        id=msg_id,
        format="metadata",
        metadataHeaders=["Subject", "From", "Date"],
        fields=METADATA_FIELDS,
    )


def to_candidate(detail):
    payload = detail.get("payload", {})
    headers = payload.get("headers", [])
    return {
        "id": detail["id"],
        "threadId": detail.get("threadId", ""),
        "internalDate": int(detail.get("internalDate", 0)),
        "date": get_real_date(extract_header(headers, "Date", "No Date")),
        "from": extract_header(headers, "From", ""),
        "subject": extract_header(headers, "Subject", "No Subject"),
        "snippet": detail.get("snippet", ""),
        # Metadata has no parts; multipart/mixed is how mail clients wrap real attachments.
        "attachment": payload.get("mimeType") == "multipart/mixed",
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

    details, _ = run_batched(service, ids, lambda msg_id: metadata_request(service, user_id, msg_id))
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
        "attachment": bool(message.get("attachment")),
        "haystack": f"{sender} {message.get('from', '')} {subject}".lower(),
    }


def column_widths(rows, total_width):
    """Return (sender, subject, snippet) widths for the space left after fixed columns."""
    fixed = 4 + 3 + 10 + 2  # cursor + checkbox, attachment, date, gap
    sender_w = min(max((cell_len(row["sender"]) for row in rows), default=6), 22)
    rest = max(0, total_width - fixed - sender_w - 2 - 1)
    longest_subject = max((cell_len(row["subject"]) for row in rows), default=7)
    subject_w = min(longest_subject, max(20, int(rest * 0.6)), rest)
    snippet_w = rest - subject_w - 2
    return sender_w, subject_w, snippet_w if snippet_w >= 10 else 0


def new_picker_state():
    """Picker state kept across runs, so cursor, filter and selection survive each action."""
    return {"cursor": 0, "top": 0, "query": "", "filtering": False, "selected": set(), "saved": set(),
            "loading": False, "exhausted": True, "confirm": None}


def pick_messages(messages, load_more=None, state=None, notice=(), can_undo=False):
    """Interactive multi-select list over messages (extended in place when older emails load).

    Returns (action, chosen messages) where action is "download" (save + trash), "save",
    "trash", "delete" (permanent), "preview", "undo" or "quit".
    load_more() returns (older messages sorted oldest first, whether even older ones remain).
    notice is a list of formatted-text lines shown under the header (last action result).
    """
    from prompt_toolkit.application import Application, get_app
    from prompt_toolkit.filters import Condition
    from prompt_toolkit.key_binding import KeyBindings
    from prompt_toolkit.layout import HSplit, Layout, Window
    from prompt_toolkit.layout.controls import FormattedTextControl
    from prompt_toolkit.layout.dimension import Dimension
    from prompt_toolkit.styles import Style

    rows = [message_row(message) for message in messages]
    state = new_picker_state() if state is None else state
    state.update(filtering=False, loading=False, confirm=None, exhausted=load_more is None)
    notice = list(notice)

    def visible():
        terms = state["query"].lower().split()
        return [i for i, row in enumerate(rows) if all(term in row["haystack"] for term in terms)]

    def size():
        return get_app().output.get_size()

    def list_height():
        # Leave room for the startup line above the picker, its own header/footer and the notice.
        return max(1, min(len(rows), size().rows - 6 - len(notice)))

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

    def current_id():
        indexes = visible()
        return messages[indexes[state["cursor"]]]["id"] if indexes else None

    def chosen():
        """Selected ids, or the email under the cursor when nothing is selected."""
        if state["selected"]:
            return set(state["selected"])
        return {current_id()} - {None}

    def render_header():
        indexes = visible()
        parts = [("class:title", " Gmail"), ("class:dim", f" · {len(rows)} emails · oldest → newest")]
        if state["query"]:
            parts.append(("class:dim", f" · {len(indexes)} match "))
            parts.append(("class:accent", state["query"]))
        return parts

    def render_notice():
        parts = []
        for line in notice:
            if parts:
                parts.append(("", "\n"))
            parts += line
        return parts

    def render_list():
        indexes = clamp()
        if not indexes:
            return [("class:dim", "   No email matches this filter." if rows else "   No emails left.")]
        sender_w, subject_w, snippet_w = column_widths(rows, size().columns)
        lines = []
        for position in range(state["top"], min(len(indexes), state["top"] + list_height())):
            index = indexes[position]
            row = rows[index]
            msg_id = messages[index]["id"]
            current = position == state["cursor"]
            if msg_id in state["selected"]:
                mark = ("class:checked", "● ")
            elif msg_id in state["saved"]:
                mark = ("class:saved", "✓ ")
            else:
                mark = ("class:dim", "○ ")
            if lines:
                lines.append(("", "\n"))
            lines += [
                ("class:cursor", " ❯ " if current else "   "),
                mark,
                ("", "📎 " if row["attachment"] else "   "),
                ("class:dim", fit(row["date"], 10) + "  "),
                ("class:sender", fit(row["sender"], sender_w) + "  "),
                ("class:subject.current" if current else "", fit(row["subject"], subject_w)),
            ]
            if snippet_w:
                lines.append(("class:dim", "  " + fit(row["snippet"], snippet_w)))
        return lines

    def render_footer():
        count = len(state["selected"])
        status = f"{count} selected " if count else ""
        if state["confirm"] and state["confirm"]["action"] == "delete":
            n = len(state["confirm"]["ids"])
            hint = [("class:error", f" Permanently delete {n} email{'s' * (n != 1)}? Cannot be undone."),
                    ("class:dim", " Type "), ("class:key", "delete"), ("class:dim", ": "),
                    ("", state["confirm"]["typed"]), ("class:accent", "▏"),
                    ("class:dim", "  enter confirm · esc cancel")]
        elif state["confirm"]:
            n = len(state["confirm"]["ids"])
            hint = [("class:warn", f" Move {n} email{'s' * (n != 1)} to trash without saving?"),
                    ("class:dim", "   "), ("class:key", "y"), ("class:dim", " confirm · any other key cancel")]
        elif state["filtering"]:
            hint = [("class:accent", " / "), ("", state["query"]), ("class:accent", "▏"),
                    ("class:dim", "   enter apply · esc clear")]
        else:
            keys = [("↑↓", "move"), ("a", "all"), ("space", "select"), ("/", "filter")]
            if not state["exhausted"]:
                keys.append(("m", "loading…" if state["loading"] else "more"))
            keys += [("p", "preview"), ("enter", "save+trash"), ("s", "save"), ("d", "trash"), ("D", "delete")]
            if can_undo:
                keys.append(("u", "undo"))
            keys.append(("q", "quit"))
            # Drop the most obvious hints first when the terminal is too narrow.
            while len(keys) > 6 and sum(cell_len(f" · {key} {label}") for key, label in keys) + cell_len(status) + 2 > size().columns:
                keys.pop(0)
            hint = []
            for key, label in keys:
                hint += [("class:dim", " · " if hint else " "), ("class:key", key), ("class:dim", f" {label}")]
        used = sum(cell_len(text) for _, text in hint)
        gap = max(2, size().columns - used - cell_len(status) - 1)
        return hint + [("", " " * gap), ("class:checked", status)]

    filtering = Condition(lambda: state["filtering"])
    confirming = Condition(lambda: bool(state["confirm"]))
    confirming_trash = Condition(lambda: bool(state["confirm"]) and state["confirm"]["action"] == "trash")
    confirming_delete = Condition(lambda: bool(state["confirm"]) and state["confirm"]["action"] == "delete")
    browsing = ~filtering & ~confirming
    bindings = KeyBindings()

    def move(delta):
        state["cursor"] += delta
        clamp()

    def submit(event, action, ids):
        if ids:
            event.app.exit(result=(action, [message for message in messages if message["id"] in ids]))

    bindings.add("up", filter=~confirming)(lambda event: move(-1))
    bindings.add("down", filter=~confirming)(lambda event: move(1))
    bindings.add("pageup", filter=~confirming)(lambda event: move(-list_height()))
    bindings.add("pagedown", filter=~confirming)(lambda event: move(list_height()))
    bindings.add("k", filter=browsing)(lambda event: move(-1))
    bindings.add("j", filter=browsing)(lambda event: move(1))
    bindings.add("home", filter=browsing)(lambda event: move(-len(rows)))
    bindings.add("end", filter=browsing)(lambda event: move(len(rows)))

    @bindings.add("space", filter=browsing)
    def _(event):
        msg_id = current_id()
        if msg_id:
            state["selected"] ^= {msg_id}
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

    bindings.add("enter", filter=browsing)(lambda event: submit(event, "download", chosen()))
    bindings.add("s", filter=browsing)(lambda event: submit(event, "save", chosen()))
    bindings.add("p", filter=browsing)(lambda event: submit(event, "preview", {current_id()} - {None}))

    def ask_confirm(action):
        ids = chosen()
        state["confirm"] = {"action": action, "ids": ids, "typed": ""} if ids else None

    bindings.add("d", filter=browsing)(lambda event: ask_confirm("trash"))
    bindings.add("D", filter=browsing)(lambda event: ask_confirm("delete"))

    bindings.add("y", filter=confirming_trash)(lambda event: submit(event, "trash", state["confirm"]["ids"]))

    @bindings.add("<any>", filter=confirming_trash)
    @bindings.add("escape", filter=confirming_delete)
    def _(event):
        state["confirm"] = None

    @bindings.add("enter", filter=confirming_delete)
    def _(event):
        if state["confirm"]["typed"] == "delete":
            submit(event, "delete", state["confirm"]["ids"])
        else:
            state["confirm"] = None

    @bindings.add("backspace", filter=confirming_delete)
    def _(event):
        state["confirm"]["typed"] = state["confirm"]["typed"][:-1]

    @bindings.add("<any>", filter=confirming_delete)
    def _(event):
        if event.data.isprintable():
            state["confirm"]["typed"] += event.data

    @bindings.add("u", filter=browsing & Condition(lambda: can_undo))
    def _(event):
        event.app.exit(result=("undo", []))

    @bindings.add("m", filter=browsing)
    def _(event):
        if state["loading"] or state["exhausted"]:
            return
        state["loading"] = True

        async def load():
            older, more = await asyncio.to_thread(load_more)
            state["exhausted"] = not more
            # Older emails go on top; keep the cursor on the same email.
            current = current_id()
            messages[:0] = older
            rows[:0] = [message_row(message) for message in older]
            if current:
                state["cursor"] = next(
                    position for position, index in enumerate(visible()) if messages[index]["id"] == current
                )
            state["loading"] = False
            event.app.invalidate()

        event.app.create_background_task(load())

    @bindings.add("q", filter=browsing)
    @bindings.add("escape", filter=browsing)
    @bindings.add("c-c")
    def _(event):
        event.app.exit(result=("quit", []))

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
        "saved": "fg:ansigreen",
        "error": "fg:ansired bold",
        "sender": "fg:ansicyan",
        "subject.current": "bold",
        "key": "bold",
        "warn": "fg:ansiyellow bold",
    })
    windows = [Window(FormattedTextControl(render_header), height=1)]
    if notice:
        windows.append(Window(FormattedTextControl(render_notice), height=len(notice)))
    windows += [
        Window(height=1),
        Window(FormattedTextControl(render_list), height=lambda: Dimension.exact(list_height())),
        Window(height=1),
        Window(FormattedTextControl(render_footer), height=1),
    ]
    app = Application(layout=Layout(HSplit(windows)), key_bindings=bindings, style=style, erase_when_done=True)
    app.ttimeoutlen = 0.05
    # Own thread: Playwright's sync API keeps an event loop running in the main one between actions.
    return app.run(in_thread=True) or ("quit", [])


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


ACTION_PREFIXES = {"s": "save", "d": "trash", "D": "delete"}


def parse_command(answer):
    """Split an optional action prefix from a typed selection.

    's 1,3' saves only, 'd 1,3' trashes, 'D 1,3' deletes permanently.
    """
    parts = (answer or "").strip().split(None, 1)
    if len(parts) == 2:
        action = ACTION_PREFIXES.get(parts[0]) or ACTION_PREFIXES.get(parts[0].lower())
        if action:
            return action, parts[1]
    return "download", answer or ""


def ask_user_to_select_messages(messages, load_more=None, state=None, notice=(), can_undo=False):
    """Pick emails interactively, or by typed numbers when not attached to a terminal.

    Returns (action, messages); see pick_messages for the actions.
    """
    if sys.stdin.isatty() and sys.stdout.isatty():
        return pick_messages(messages, load_more, state, notice, can_undo)
    if not messages:
        return "quit", []

    for line in notice:
        # Key hints only make sense in the interactive picker.
        console.print(escape("".join(text for style, text in line if "keyhint" not in style)))
    sender_w = min(max(cell_len(sender_name(m.get("from"))) for m in messages), 22)
    num_w = len(str(len(messages)))
    for number, message in enumerate(messages, start=1):
        row = message_row(message)
        subject_w = max(10, console.width - num_w - 18 - sender_w)
        console.print(escape(f" {number:>{num_w}}  {fit(row['date'], 10)}  {fit(row['sender'], sender_w)}  {fit(row['subject'], subject_w)}"))
    while True:
        try:
            answer = input("\nSelect (e.g. 1,3 · 2-6 · all · s 1,3 save only · d 1,3 trash · D 1,3 delete · q) > ")
        except EOFError:
            return "quit", []
        action, selection = parse_command(answer)
        try:
            chosen = [messages[index] for index in parse_selection(selection, len(messages))]
        except ValueError as exc:
            warn(f"{exc}. Try again.")
            continue
        if not chosen:
            return "quit", []
        if action == "trash":
            try:
                confirm = input(f"Move {len(chosen)} email(s) to trash without saving? [y/N] ")
            except EOFError:
                return "quit", []
            if confirm.strip().lower() not in {"y", "yes", "o", "oui"}:
                continue
        if action == "delete":
            try:
                confirm = input(f"Permanently delete {len(chosen)} email(s)? Cannot be undone. Type delete: ")
            except EOFError:
                return "quit", []
            if confirm.strip() != "delete":
                continue
        return action, chosen


def html_to_text(content):
    """Rough HTML → readable text, good enough for a terminal preview."""
    content = re.sub(r"(?is)<(script|style|head)\b.*?</\1\s*>", "", content)
    content = re.sub(r"(?i)<br\s*/?>|</(p|div|tr|li|h\d|table)\s*>", "\n", content)
    content = html.unescape(re.sub(r"<[^>]+>", "", content))
    content = re.sub(r"[ \t\xa0]+", " ", content)
    return re.sub(r"\n\s*\n+", "\n\n", content).strip()


def message_text(msg):
    """Body of a parsed email as text: the plain part, else the HTML part converted."""
    part = msg.get_body(preferencelist=("plain", "html"))
    if part is None:
        return "No content found in email."
    try:
        content = part.get_content()
    except Exception:
        content = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
    return html_to_text(content) if part.get_content_type() == "text/html" else content.strip()


def preview_message(service, user_id, message):
    with console.status("[dim]Loading email…[/]"):
        raw = service.users().messages().get(userId=user_id, id=message["id"], format="raw").execute()["raw"]
    msg = BytesParser(policy=policy_default).parse(io.BytesIO(base64.urlsafe_b64decode(raw)))
    attachments = [
        part.get_filename() for part in msg.walk()
        if part.get_filename() and part.get_content_disposition() == "attachment"
    ]
    with console.pager():
        console.print(escape(msg["Subject"] or "No Subject"))
        for name in ("From", "To", "Cc", "Date"):
            if msg[name]:
                console.print(f"{name}: {escape(str(msg[name]))}")
        if attachments:
            console.print(f"Attachments: {escape(', '.join(attachments))}")
        console.print()
        console.print(escape(message_text(msg)))


def save_messages(service, user_id, messages, save_dir, browser, trash_after):
    """Save emails as PDFs + attachments, then (optionally) trash the saved ones in one batch.

    Returns (saved messages, attachment count, {id: error text}).
    """
    sender_w = min(max(cell_len(sender_name(m.get("from"))) for m in messages), 22)
    results, failed = {}, {}
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[dim]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        console=console,
        transient=True,
    )
    with progress:
        task = progress.add_task("", total=len(messages))
        for message in messages:
            subject = fit(message.get("subject") or "No Subject", 40).rstrip()

            def on_step(step):
                progress.update(task, description=escape(f"{subject} · {step}…"))

            try:
                result = save_email_and_attachments(service, user_id, message["id"], save_dir, browser, on_step)
            except Exception as exc:
                failed[message["id"]] = str(exc)
                print_message_line("[red]✗[/]", message, "failed", sender_w)
                console.print(f"      [dim]└ {escape(str(exc))}[/]")
            else:
                results[message["id"]] = result
                count = result["attachments"]
                detail = f"PDF + {count} attachment{'s' * (count > 1)}" if count else "PDF"
                print_message_line("[green]✓[/]", message, detail, sender_w)
            progress.advance(task)

        if trash_after and results:
            progress.update(task, description="moving to trash…")
            for msg_id, exc in trash_messages(service, user_id, list(results)).items():
                # Email stays in Gmail, so drop its files to keep a retry duplicate-free.
                remove_files(results.pop(msg_id)["files"])
                failed[msg_id] = f"could not move to trash: {exc}"

    saved = [message for message in messages if message["id"] in results]
    return saved, sum(result["attachments"] for result in results.values()), failed


def plural(count, word):
    return f"{count} {word}{'s' * (count != 1)}"


def failure_notice(messages, failed, limit=3):
    """Notice lines for failed emails (they stay in Gmail and selected, ready for a retry)."""
    by_id = {message["id"]: message for message in messages}
    lines = []
    for msg_id, error in list(failed.items())[:limit]:
        subject = fit(by_id[msg_id].get("subject") or "No Subject", 40).rstrip()
        lines.append([("class:error", " ✗ "), ("", subject), ("class:dim", " · " + fit(str(error), 80).rstrip())])
    if len(failed) > limit:
        lines.append([("class:dim", f"   … and {len(failed) - limit} more failed")])
    return lines


def interactive_download_main():
    import argparse

    parser = argparse.ArgumentParser(
        description=(
            "List available Gmail messages, let the user choose which ones to download as PDFs "
            "(and move to the Gmail trash), keep as is, or trash without saving."
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
    playwright = browser = None
    try:
        service = build("gmail", "v1", credentials=creds)
        user_id = "me"
        save_dir = os.path.expanduser(args.download_path)
        os.makedirs(save_dir, exist_ok=True)
        shown_dir = save_dir.replace(os.path.expanduser("~"), "~", 1)

        account = service.users().getProfile(userId=user_id).execute().get("emailAddress", user_id)
        banner = (
            f" [bold]savegmail[/]  [dim]·[/]  {escape(account)}  [dim]·  query:[/] "
            f"{escape(args.query) if args.query else '[dim](all)[/]'}  [dim]·  →[/] {escape(shown_dir)}\n"
        )
        console.print(banner)
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

        def drop(ids):
            messages[:] = [message for message in messages if message["id"] not in ids]
            state["selected"] -= ids

        state = new_picker_state()
        notice, last_trashed = [], []
        totals = {"saved": 0, "trashed": 0, "deleted": 0}
        # Back to the list after every action, until the user quits.
        while messages or next_page or last_trashed:
            action, chosen = ask_user_to_select_messages(
                messages, load_more if next_page else None, state, notice, bool(last_trashed)
            )
            if action == "quit" or (action != "undo" and not chosen):
                break
            ids = {message["id"] for message in chosen}

            if action == "preview":
                preview_message(service, user_id, chosen[0])

            elif action == "undo":
                with console.status("[dim]Restoring from trash…[/]"):
                    errors = untrash_messages(service, user_id, [message["id"] for message in last_trashed])
                restored = [message for message in last_trashed if message["id"] not in errors]
                messages.extend(restored)
                messages.sort(key=lambda message: message["internalDate"])
                notice = [[("class:checked", " ↶ "), ("", f"{plural(len(restored), 'email')} restored from trash")]]
                notice += failure_notice(last_trashed, {msg_id: str(exc) for msg_id, exc in errors.items()})
                totals["trashed"] -= len(restored)
                last_trashed = [message for message in last_trashed if message["id"] in errors]

            elif action == "trash":
                with console.status("[dim]Moving to trash…[/]"):
                    errors = trash_messages(service, user_id, list(ids))
                trashed = [message for message in chosen if message["id"] not in errors]
                drop({message["id"] for message in trashed})
                if trashed:
                    last_trashed = trashed
                totals["trashed"] += len(trashed)
                notice = [[("class:checked", " ✓ "), ("", f"{plural(len(trashed), 'email')} moved to trash (not saved)"),
                           ("class:dim class:keyhint", " · u undo" if trashed else "")]]
                notice += failure_notice(chosen, {msg_id: str(exc) for msg_id, exc in errors.items()})

            elif action == "delete":
                try:
                    with console.status("[dim]Deleting…[/]"):
                        delete_messages(service, user_id, list(ids))
                except Exception as exc:
                    # batchDelete is all-or-nothing: nothing was deleted.
                    notice = [[("class:error", " ✗ "), ("", f"Could not delete {plural(len(ids), 'email')}"),
                               ("class:dim", " · " + fit(str(exc), 80).rstrip())]]
                else:
                    drop(ids)
                    totals["deleted"] += len(ids)
                    notice = [[("class:checked", " ✓ "), ("", f"{plural(len(ids), 'email')} permanently deleted")]]

            else:
                if browser is None:
                    playwright = sync_playwright().start()
                    with console.status("[dim]Preparing Chromium…[/]"):
                        browser = launch_browser(playwright, headed=args.headed)
                trash_after = action == "download"
                saved, attachments, failed = save_messages(service, user_id, chosen, save_dir, browser, trash_after)
                saved_ids = {message["id"] for message in saved}
                totals["saved"] += len(saved)
                summary = f"{plural(len(saved), 'PDF')} · {plural(attachments, 'attachment')}"
                if trash_after:
                    drop(saved_ids)
                    if saved:
                        last_trashed = saved
                    totals["trashed"] += len(saved)
                    summary += " · moved to trash"
                else:
                    state["selected"] -= saved_ids
                    state["saved"] |= saved_ids
                    summary += " · kept in Gmail"
                notice = [[("class:checked", " ✓ "), ("", summary), ("class:dim", f" → {shown_dir}")]]
                if trash_after and saved:
                    notice[0].append(("class:dim class:keyhint", " · u undo"))
                notice += failure_notice(chosen, failed)

            console.clear()
            console.print(banner)

        if not (messages or next_page):
            console.print("[dim]No emails left.[/]")
        if any(totals.values()):
            summary = f"{plural(totals['saved'], 'email')} saved · {totals['trashed']} moved to trash"
            if totals["deleted"]:
                summary += f" · {totals['deleted']} permanently deleted"
            console.print(f" [bold]Done[/] [dim]·[/] {summary}\n [dim]→[/] {escape(shown_dir)}")

    except HttpError as error:
        console.print(f"[red]✗[/] Gmail API error: {escape(str(error))}")
    finally:
        if browser is not None:
            browser.close()
        if playwright is not None:
            playwright.stop()

if __name__ == "__main__":
    interactive_download_main()
