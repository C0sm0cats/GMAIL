import os
import pathlib
import base64
from playwright.sync_api import Error as PlaywrightError, sync_playwright
import asyncio
from datetime import datetime, timezone
from google.auth.exceptions import RefreshError, TransportError
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import httplib2
from tzlocal import get_localzone
from email.utils import parsedate_to_datetime
import subprocess
import sys
import logging
import re
import io
import contextlib
import shutil
import time
import tempfile
import threading
import uuid
import webbrowser
from urllib.parse import quote
import html
import mimetypes
from email.parser import BytesParser
from email.policy import default as policy_default
from email.utils import getaddresses, parseaddr
from rich.cells import cell_len
from rich.console import Console
from rich.markup import escape
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn

logging.getLogger('tzlocal').setLevel(logging.ERROR)

console = Console(highlight=False)
VERBOSE = False
ACCOUNT = None  # signed-in address, so emails sent to yourself show "Sent · me"
USER_LABELS = {}  # your own Gmail label ids -> names, shown and filterable like categories


def debug(message):
    if VERBOSE:
        console.print(f"[dim]  {escape(message)}[/]")


def warn(message):
    console.print(f"[yellow]![/] {escape(message)}")

# Python's header parser takes time and memory quadratic in a header's length: a sender's few hundred KB
# of encoded-words in a subject, address or attachment name would take several GB. Longer headers are cut
# before parsing; 32 KB is already far more than the PDF header can show.
MAX_HEADER_CHARS = 32 * 1024


class CappedHeaderPolicy(type(policy_default)):
    def header_fetch_parse(self, name, value):
        if isinstance(value, str):
            value = value[:MAX_HEADER_CHARS]
        return super().header_fetch_parse(name, value)


capped_header_policy = CappedHeaderPolicy()

# Inline images are served at these URLs, once each, instead of being pasted into the HTML as data: URLs:
# an email referencing one image a thousand times would otherwise make a HTML a thousand times its size.
INLINE_IMAGE_URL = "https://cid.savegmail.invalid/{}"

# A sender's forced page breaks or a very tall element can make Chromium print tens of thousands of pages,
# in a time quadratic in their number (minutes per email). Real emails stay far below this many pages.
MAX_PDF_PAGES = 1000

# Longest wait for an email's images and fonts before printing; one that never answers is printed without.
IMAGE_WAIT_SECONDS = 15


def new_email_page(browser, resources=None):
    """Open a page for content written by a sender: its scripts never run, and it never navigates away
    (a meta refresh would otherwise replace the email with a page of the sender's choice, or an error page).

    resources maps URLs to (content_type, body) served by the page itself (the email's inline images).
    """
    page = browser.new_page(java_script_enabled=False)
    resources = resources or {}

    def handle(route):
        request = route.request
        if request.is_navigation_request() and request.frame == page.main_frame:
            route.fulfill(status=204)  # 204 keeps the current document; abort() would show an error page
        elif request.url in resources:
            content_type, body = resources[request.url]
            route.fulfill(status=200, content_type=content_type, body=body)
        else:
            route.continue_()

    page.route("**/*", handle)
    return page

def measure_pdf_margins(browser, header_template, footer_template):
    """Measure isolated print templates at A4 width, including wrapped lines."""
    measurement_page = new_email_page(browser)
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
        except (TypeError, ValueError):
            # Python < 3.10 raises TypeError on an unparseable date.
            parsed_date = None
        else:
            # "-0000" (or an unknown zone name) means UTC, sender zone unknown
            # (RFC 5322 §3.3, §4.3); Python returns it without tzinfo.
            if parsed_date.tzinfo is None:
                parsed_date = parsed_date.replace(tzinfo=timezone.utc)
    if not parsed_date:
        return 'Invalid Date'
    try:
        local_date = parsed_date.astimezone(get_localzone())
    except (OverflowError, ValueError):
        # A year at the edge of 1..9999 cannot be shifted to the local zone.
        return 'Invalid Date'
    return local_date.strftime("%Y-%m-%d %H:%M:%S %Z")


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


SIGN_IN_SUCCESS_PAGE = "savegmail: signed in. You can close this tab."


def open_quietly(url):
    """Open url in the default browser without letting the browser write to our terminal.

    Falls back to Python's webbrowser (which honors $BROWSER) when no system opener is usable.
    """
    opener = "open" if sys.platform == "darwin" else "xdg-open"
    if sys.platform != "win32" and not os.environ.get("BROWSER") and shutil.which(opener):
        try:
            subprocess.Popen([opener, url], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, start_new_session=True)
            return True
        except OSError:
            pass
    return webbrowser.open(url)


def sign_in(reason):
    """Browser OAuth sign-in with compact output, erased once signed in (kept with --verbose)."""
    flow = oauth_flow()

    class QuietBrowser(webbrowser.BaseBrowser):
        # run_local_server hands us the sign-in URL here, so the prompt and opening are ours.
        def open(self, url, new=0, autoraise=True):
            console.print(f"[yellow]![/] {reason}")
            console.print(f"  [dim]Didn't open?[/] [link={url}]Open the sign-in page[/link]")
            if VERBOSE:
                # Soft wrap keeps the URL one logical line, so terminals still detect it as a link.
                console.print(f"  {url}", style="dim", markup=False, soft_wrap=True)
            return open_quietly(url)

    webbrowser.register("savegmail", None, QuietBrowser("savegmail"))
    with console.status("[dim]Waiting for sign-in…[/]"):
        creds = flow.run_local_server(
            port=0, browser="savegmail", authorization_prompt_message="", success_message=SIGN_IN_SUCCESS_PAGE
        )
    if not VERBOSE and console.is_terminal:
        console.file.write("\x1b[2F\x1b[J")  # erase the two prompt lines
    debug(f"Token expires {convert_expiry_to_local_time(creds.expiry)}")
    return creds


def sign_in_quietly(timeout=300):
    """Browser OAuth sign-in that prints nothing, for use while the list is on screen."""
    flow = oauth_flow()

    class SilentBrowser(webbrowser.BaseBrowser):
        def open(self, url, new=0, autoraise=True):
            return open_quietly(url)

    webbrowser.register("savegmail-silent", None, SilentBrowser("savegmail-silent"))
    creds = flow.run_local_server(port=0, browser="savegmail-silent", authorization_prompt_message="",
                                  success_message=SIGN_IN_SUCCESS_PAGE, timeout_seconds=timeout)
    with open(TOKEN_PATH, "w") as token:
        token.write(creds.to_json())
    return creds


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
                debug(f"Could not refresh token: {e}")
                if "invalid_grant" in str(e):
                    reason = "Gmail session expired, sign in again in your browser."
                else:
                    reason = "Could not refresh the Gmail session, sign in again in your browser."
                creds = sign_in(reason)
        else:
            creds = sign_in("Sign in to Gmail in your browser.")
        with open(TOKEN_PATH, "w") as token:
            token.write(creds.to_json())
    return creds

def truncate_bytes(text, limit):
    """Cut text to at most limit UTF-8 bytes without splitting a character."""
    return text.encode("utf-8")[:limit].decode("utf-8", "ignore")


def in_background(fn, *args):
    """Await fn(*args) run in a daemon thread, unlike asyncio.to_thread: leaving the list never waits for it.

    An abandoned call keeps running and its result is dropped.
    """
    loop = asyncio.get_running_loop()
    future = loop.create_future()

    def settle(setter, value):
        if not future.done():
            setter(value)

    def work():
        try:
            value, setter = fn(*args), future.set_result
        except BaseException as exc:
            value, setter = exc, future.set_exception
        try:
            loop.call_soon_threadsafe(settle, setter, value)
        except RuntimeError:
            pass  # the list is gone (its event loop is closed)

    threading.Thread(target=work, daemon=True).start()
    return future


def discard_pending_keys(app_input=None):
    """Drop keys typed while an action ran, so they never trigger actions blindly.

    Key auto-repeat while a PDF viewer grabbed the focus once queued p presses that kept relaunching
    previews, one per run of the list.
    """
    if sys.stdin.isatty():
        try:
            import termios
        except ImportError:
            termios = None  # Windows: nothing more to drop than the typeahead below
        if termios:
            try:
                termios.tcflush(sys.stdin.fileno(), termios.TCIFLUSH)
            except (termios.error, OSError):
                pass
    if app_input is not None:
        from prompt_toolkit.input.typeahead import clear_typeahead
        clear_typeahead(app_input)


def remove_files(paths):
    for path in paths:
        with contextlib.suppress(FileNotFoundError):
            os.remove(path)


def save_email_and_attachments(service, user_id, msg_id, save_dir, browser, on_step=lambda step: None,
                               save_attachments=True):
    """Save one email as PDF + attachments; on failure, remove what was written so a retry starts clean.

    save_attachments=False renders the PDF only (attachments are listed, not written), for previews.
    """
    written = []
    try:
        return write_email_files(service, user_id, msg_id, save_dir, browser, on_step, written, save_attachments)
    except Exception:
        remove_files(written)
        raise


def format_addresses(value):
    """An address header as escaped HTML text: every `Name address`, or the raw value if it does not parse."""
    value = str(value or "")
    pairs = getaddresses([value])
    if not pairs or not all(addr for _, addr in pairs):
        return html.escape(value)
    return html.escape(", ".join(f"{name} {addr}" if name else addr for name, addr in pairs))

def write_email_files(service, user_id, msg_id, save_dir, browser, on_step, written, save_attachments=True):
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
        safe = re.sub(r'[<>"|?\x00-\x1f]', "-", safe)  # forbidden on Windows, plus control chars
        # Linux caps file names at 255 bytes; leave room for the timestamp prefix and ".pdf".
        safe = truncate_bytes(safe.strip(), 150).rstrip(". ")
        return safe or "No_Subject"

    on_step("fetching")
    message = service.users().messages().get(userId=user_id, id=msg_id, format='raw').execute()
    raw = message['raw']
    email_bytes = base64.urlsafe_b64decode(raw)
    msg = BytesParser(policy=capped_header_policy).parse(io.BytesIO(email_bytes))

    # Extract headers
    subject = msg['Subject'] or ""
    file_safe_subject = sanitize_subject_for_filename(subject)
    # Every header value is the sender's text: escape it, or a `<` in it is read as HTML by Chromium.
    fro = format_addresses(msg['From'])
    reply = format_addresses(msg['Reply-To'])
    to = format_addresses(msg['To'])
    cc = format_addresses(msg['Cc'])
    date = html.escape(get_real_date(msg['Date'] or 'No Date'))

    def plain_to_html(text):
        plain_text = html.escape(text)  # `<` and `&` are text, not HTML
        plain_text = re.sub(r'(>>?|>)', r'\1', plain_text)
        plain_text = re.sub(r'(On \d{2}/\d{2}/\d{4})', r'\n\n\1', plain_text)
        date_regex = r'((Le|The) \d{1,2} (janv\.|févr\.|mars\.|avr\.|mai\.|juin\.|juil\.|août\.|sept\.|oct\.|nov\.|déc\.|Jan\.|Feb\.|Mar\.|Apr\.|May\.|Jun\.|Jul\.|Aug\.|Sep\.|Oct\.|Nov\.|Dec\.) \d{4}( (à|at) \d{1,2}:\d{2})?)'
        plain_text = re.sub(date_regex, r'\n\n\1', plain_text)
        # The text is escaped: an URL stops at an escaped `<`, `>` or `"`, as it did before escaping.
        url_regex = r'((?:https?://|www\.)(?:(?!&lt;|&gt;|&quot;)\S)+)'
        plain_text = re.sub(url_regex, r'<a href="\1" target="_blank">\1</a>', plain_text)
        # pre-wrap keeps line breaks and the spaces that align columns, and still wraps long lines;
        # a monospace font keeps those columns aligned, as mail clients show plain text.
        return f'<div style="font-family: monospace;font-size: 10px;white-space: pre-wrap">{plain_text}</div>'

    def body_text(part):
        # get_content() decodes with the declared charset, ASCII when there is none (every accent
        # becomes U+FFFD), and raises LookupError on a name Python does not know (unknown-8bit,
        # x-mac-roman, x-user-defined): the email could then never be saved.
        data = part.get_payload(decode=True) or b""
        names = [part.get_content_charset()]
        if part.get_content_subtype() == 'html':  # an HTML part often declares it in a <meta> only
            meta = re.search(rb'<meta[^>]*charset\s*=\s*["\']?\s*([A-Za-z0-9_.:-]+)', data[:8192], re.I)
            names.append(meta and meta.group(1).decode('ascii').lower())
        for name in filter(None, names):
            for codec in (name, name[2:]) if name.startswith('x-') else (name,):
                try:
                    return data.decode(codec, errors='replace')
                except LookupError:
                    continue
        try:
            return data.decode('utf-8')
        except UnicodeDecodeError:
            return data.decode('cp1252', errors='replace')

    def body_parts(part):
        # The text parts a reader sees, in order. get_body() returns only one, but a body can be split
        # around an attachment (Apple Mail) or end with a footer in its own part (mailing lists).
        if part.get_content_maintype() != 'multipart':
            if (part.get_content_type() in ('text/html', 'text/plain') and not part.get_filename()
                    and part.get_content_disposition() != 'attachment'):
                return [part]
            return []
        subparts = part.get_payload()
        subtype = part.get_content_subtype()
        if subtype == 'alternative':  # one rendering of the same text: the HTML one, or else the last
            choices = [parts for parts in map(body_parts, subparts) if parts]
            with_html = [parts for parts in choices if any(p.get_content_subtype() == 'html' for p in parts)]
            return (with_html or choices or [[]])[-1]
        if subtype == 'related':  # the root, the other parts are its images
            return body_parts(subparts[0]) if subparts else []
        return [p for sub in subparts for p in body_parts(sub)]

    # Extract HTML or plain text
    body = msg.get_body(preferencelist=('html',)) or msg.get_body(preferencelist=('plain',))
    parts = body_parts(msg) if body else []
    if body is not None and not any(p is body for p in parts):
        parts = [body]  # a body we would not pick ourselves (e.g. named inline text): keep get_body's
    if len(parts) > 1:
        debug(f"Email body selected: {len(parts)} text parts")
    if parts:
        segments = [body_text(p) if p.get_content_subtype() == 'html' else plain_to_html(body_text(p))
                    for p in parts]
        if parts[0].get_content_subtype() == 'html':
            debug("Email body selected: HTML")
            # Chromium merges the <html> and <body> of the later parts into the first document.
            html_content = "\n".join(segments)
        else:
            debug("Email body selected: plain text")
            joined = "\n".join(segments)
            html_content = f"""<html>
            <body>
                {joined}
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
        # Windows silently drops trailing dots/spaces, so the saved name would differ from ours.
        filename = (base + ext).rstrip(". ") or "attachment"
        base, ext = os.path.splitext(filename)
        counter = 1
        candidate = filename

        while (os.path.exists(os.path.join(save_dir, candidate)) or 
               candidate in used_filenames):
            candidate = f"{base}({counter}){ext}"
            counter += 1

        used_filenames.add(candidate)
        return candidate

    def attachment_name(part):
        # The sender's file name, or one of ours for a part sent as an attachment without a name
        # (scanners, invoicing tools; Gmail shows "noname"): it is still a file to keep.
        name = part.get_filename()
        if not name and part.get_content_disposition() == 'attachment':
            name = "attachment" + (mimetypes.guess_extension(part.get_content_type()) or ".bin")
        return name

    def walk(part):
        # Like msg.walk(), but an attached email (message/rfc822 with a name) is one attachment: its own
        # parts belong to it, not to this email.
        yield part
        if part.is_multipart() and not (part.get_content_maintype() == 'message' and attachment_name(part)):
            for sub in part.get_payload():
                yield from walk(sub)

    def attachment_bytes(part):
        if part.is_multipart():  # message/rfc822 and other message/* types: get_payload(decode=True) is None
            return b"".join(sub.as_bytes() for sub in part.get_payload())
        return part.get_payload(decode=True)

    for part in walk(msg):
        debug(f"Part: Content-Type={part.get_content_type()}, Content-ID={part.get('Content-ID')}, Filename={part.get_filename()}, Disposition={part.get_content_disposition()}")
        if part.get_content_maintype() == 'multipart':
            continue
        original_filename = attachment_name(part)
        filename = clean_filename(original_filename) if original_filename else None
        content_type = part.get_content_type()
        content_id = part.get('Content-ID')
        content_disposition = part.get_content_disposition()  # New: Get disposition

        # Handle true attachments: Save if filename and disposition is 'attachment' (or no CID for safety)
        if filename and (content_disposition == 'attachment' or not content_id):
            attachments_files.append(filename)
            if save_attachments:
                payload = attachment_bytes(part)
                path = os.path.join(save_dir, filename)
                written.append(path)
                with open(path, 'wb') as f:
                    f.write(payload)
                debug(f"Attachment saved: {filename}")

        # Handle images (inline or otherwise): Always embed if image and has CID
        if content_type.startswith('image/'):
            image = (content_type, part.get_payload(decode=True))
            if content_id:
                content_id = content_id.strip('<>')
                cid_map[content_id] = image
                debug(f"Mapped CID {content_id} to an inline {content_type} image")
            elif not filename:  # Generate CID only for true inline without filename
                generated_cid = f"generated_cid_{counter}"
                cid_map[generated_cid] = image
                debug(f"Generated CID {generated_cid} for inline {content_type} image without Content-ID")
                counter += 1

    # Point each cid: at one URL per image, served by the page (see INLINE_IMAGE_URL).
    inline_images = {}
    cid_urls = {}

    def replace_cid(match):
        cid_value = match.group(1)
        if cid_value in cid_map:
            if cid_value not in cid_urls:
                cid_urls[cid_value] = INLINE_IMAGE_URL.format(len(cid_urls))
                inline_images[cid_urls[cid_value]] = cid_map[cid_value]
            debug(f"Replacing CID: {cid_value} with {cid_urls[cid_value]}")
            return f'src="{cid_urls[cid_value]}"'
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
            attachment_url = pathlib.Path(os.path.abspath(attachment_path)).as_uri()  # file:///C:/… on Windows
            # Previews don't write attachments, so there is no file to link to.
            name = html.escape(attachment)
            label = f"<a href='{html.escape(attachment_url)}'>{name}</a>" if save_attachments else name
            attachments_html_footer += f"  <li style='margin-bottom: 0;'><h6 style='margin: 0; padding: 0;'>{label}</h6></li>\n"
        attachments_html_footer += "</ul>\n"
    else:
        attachments_html_footer = "<div>No attachments for this mail</div>"

    # Generate PDF. Render under a name of our own: the subject may match an attachment of this email
    # or a file already in the folder, which would be overwritten, or removed if the save fails.
    final_pdf_path = os.path.join(save_dir, f".savegmail-{uuid.uuid4().hex}.pdf")
    written.append(final_pdf_path)

    on_step("rendering PDF")
    page = new_email_page(browser, inline_images)
    try:
        # Not "networkidle": a remote image whose server never answers would hold it until the timeout;
        # images and fonts get their own, shorter, wait below.
        page.set_content(html_content, timeout=120000, wait_until="domcontentloaded")
        # Emails often defer images; force them in and wait for fonts/images before printing.
        page.evaluate("""() => {
            document.querySelectorAll('img[data-src]').forEach(img => {
                if (!img.getAttribute('src')) img.src = img.dataset.src;
            });
            document.querySelectorAll('img[loading="lazy"]').forEach(img => img.loading = 'eager');
        }""")
        # With scripts disabled, the page runs no timers or load listeners: poll from here instead.
        deadline = time.monotonic() + IMAGE_WAIT_SECONDS
        while time.monotonic() < deadline and not page.evaluate(
                "[...document.images].every(img => img.complete) && document.fonts.status === 'loaded'"):
            page.wait_for_timeout(100)
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
        """.format(fro=fro, reply=reply, to=to, cc=cc, date=date, subject=html.escape(subject))
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
            page_ranges=f"1-{MAX_PDF_PAGES}",
            path=final_pdf_path
        )
    except Exception as e:
        raise RuntimeError(f"PDF generation failed: {e}") from e
    finally:
        page.close()

    now = datetime.now()
    timestamp = now.strftime("%y%m%d_%H%M%S")
    milliseconds = now.microsecond // 1000
    base = f"{timestamp}{milliseconds}_{file_safe_subject}"
    new_pdf_name, counter = f"{base}.pdf", 1
    while os.path.exists(os.path.join(save_dir, new_pdf_name)) or new_pdf_name in used_filenames:
        new_pdf_name = f"{base}({counter}).pdf"
        counter += 1
    new_pdf_path = os.path.join(save_dir, new_pdf_name)
    os.rename(final_pdf_path, new_pdf_path)
    written[-1] = new_pdf_path
    debug(f"Saved {os.path.basename(new_pdf_path)}")
    return {"pdf": os.path.basename(new_pdf_path), "attachments": len(attachments_files), "files": written}

def empty_trash(service):
    """
    Permanently deletes all messages from the trash, after confirmation.
    """
    try:
        with console.status("[dim]Listing trash…[/]"):
            ids = list_trash_ids(service, 'me')

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

    except PartialBatchError as e:
        console.print(f"[red]✗[/] {len(e.done)} message(s) permanently deleted from trash, then: {escape(str(e))}")
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
        chunk = ids[start:start + API_BATCH_SIZE]
        batch = service.new_batch_http_request(callback=collect)
        for msg_id in chunk:
            batch.add(make_request(msg_id), request_id=msg_id)
        try:
            batch.execute()
        except Exception as exc:
            # The batch call itself failed (5xx, quota, network): its unanswered entries count as failed.
            debug(f"Gmail batch request failed: {exc}")
            for msg_id in chunk:
                if msg_id not in responses:
                    errors.setdefault(msg_id, exc)

    # Retry throttled/failed batch entries one by one.
    pending = list(errors)
    for index, msg_id in enumerate(pending):
        try:
            responses[msg_id] = make_request(msg_id).execute()
            del errors[msg_id]
        except Exception as exc:
            errors[msg_id] = exc
            debug(f"Gmail request failed for message {msg_id}: {exc}")
            if isinstance(exc, GMAIL_ERRORS) and not isinstance(exc, HttpError):
                # Session expired or network down: the other retries would fail the same way.
                errors.update({other: exc for other in pending[index + 1:]})
                break
    return responses, errors


def user_labels(service, user_id):
    """Your own Gmail labels, {id: name} (system labels and categories left out)."""
    try:
        labels = service.users().labels().list(userId=user_id).execute().get("labels", [])
    except HttpError as exc:
        debug(f"Could not list labels: {exc}")
        return {}
    return {label["id"]: label["name"] for label in labels if label.get("type") == "user"}


def current_labels(service, user_id, ids):
    """{id: labels} as Gmail has them now (read / unread, star, Inbox…)."""
    details, _ = run_batched(service, list(ids), lambda msg_id:
                             service.users().messages().get(userId=user_id, id=msg_id, format="minimal",
                                                            fields="id,labelIds"))
    return {msg_id: detail["labelIds"] for msg_id, detail in details.items() if "labelIds" in detail}


def refresh_labels(service, user_id, messages):
    """Re-read the labels of loaded emails, changed in Gmail meanwhile.

    Updates messages in place; returns how many changed.
    """
    fresh = current_labels(service, user_id, [message["id"] for message in messages])
    changed = 0
    for message in messages:
        labels = fresh.get(message["id"])
        if labels is not None and set(labels) != set(message.get("labels", [])):
            message["labels"] = labels
            changed += 1
    return changed


# What a Gmail call raises besides HttpError: session expired or revoked (RefreshError), network down
# (httplib2's ServerNotFoundError, google-auth's TransportError, OSError such as timeouts and resets).
GMAIL_ERRORS = (HttpError, RefreshError, TransportError, httplib2.HttpLib2Error, OSError)


def mark_read(service, user_id, messages):
    """Mark emails as read in Gmail and locally (preview and open count as reading them)."""
    unread = [message for message in messages if "UNREAD" in message.get("labels", [])]
    if not unread:
        return
    try:
        modify_labels(service, user_id, [message["id"] for message in unread], remove=["UNREAD"])
    except PartialBatchError as exc:
        debug(f"Could not mark as read: {exc}")
        done = set(exc.done)
        unread = [message for message in unread if message["id"] in done]
    except GMAIL_ERRORS as exc:
        debug(f"Could not mark as read: {exc}")
        return
    for message in unread:
        message["labels"] = [label for label in message["labels"] if label != "UNREAD"]


class PartialBatchError(Exception):
    """A call per 1000 ids failed after earlier ones went through: done lists their ids, error is Gmail's."""

    def __init__(self, done, error):
        super().__init__(str(error))
        self.done, self.error = done, error


def per_thousand(ids, call):
    """call(chunk) for every 1000 ids (Gmail's limit); each call stands alone, so a failure after the first
    raises PartialBatchError with the ids already done, and a failure of the first one raises as is."""
    ids = list(ids)
    for start in range(0, len(ids), 1000):
        try:
            call(ids[start:start + 1000])
        except Exception as exc:
            if start:
                raise PartialBatchError(ids[:start], exc) from exc
            raise


def batch_outcome(call, errors=Exception):
    """(ids done, error) of a modify_labels / delete_messages call: (None, None) when all went through."""
    try:
        call()
    except PartialBatchError as exc:
        return set(exc.done), exc.error
    except errors as exc:
        return set(), exc
    return None, None


def modify_labels(service, user_id, ids, add=(), remove=()):
    """Add / remove Gmail labels (STARRED, INBOX, SPAM…) on messages, in one call per 1000."""
    per_thousand(ids, lambda chunk: service.users().messages().batchModify(
        userId=user_id, body={"ids": chunk, "addLabelIds": list(add), "removeLabelIds": list(remove)}).execute())


def gmail_url(account, msg_id):
    # authuser picks the right account when several are signed in (an address in /u/<…>/ gives a 404).
    return f"https://mail.google.com/mail/?authuser={quote(account)}#all/{msg_id}"


def list_trash_ids(service, user_id):
    ids = []
    request = service.users().messages().list(userId=user_id, labelIds=['TRASH'], maxResults=500)
    while request is not None:
        results = request.execute()
        ids.extend(message['id'] for message in results.get('messages', []))
        request = service.users().messages().list_next(request, results)
    return ids


def delete_messages(service, user_id, ids):
    """Permanently delete messages, bypassing the trash. Cannot be undone."""
    per_thousand(ids, lambda chunk: service.users().messages().batchDelete(
        userId=user_id, body={"ids": chunk}).execute())


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


METADATA_FIELDS = "id,threadId,internalDate,labelIds,sizeEstimate,payload(mimeType,headers),snippet"
# Tab cycles through these views; each is the Gmail search added to --query.
# Archived is ours, not a Gmail label: archiving only removes INBOX, so it is All mail minus the rest.
VIEWS = [("All mail", ""), ("Inbox", "in:inbox"), ("Archived", "-in:inbox -in:sent -in:drafts -in:chats"),
         ("Starred", "is:starred"), ("Sent", "in:sent"),
         ("Drafts", "in:drafts"), ("Spam", "in:spam"), ("Trash", "in:trash")]
# Each view's color, for its tab and the header info, so you see at a glance where you are.
# Sent and Drafts match their sender colors in the list.
VIEW_COLORS = {"All mail": "ansicyan", "Inbox": "ansiblue", "Archived": "ansigreen", "Starred": "ansiyellow",
               "Sent": "ansimagenta", "Drafts": "ansired", "Spam": "#ff8700", "Trash": "#8a8a8a"}
# Gmail category labels, shown as a short tag (Primary has no tag, like in Gmail).
CATEGORIES = {"CATEGORY_PROMOTIONS": "Promotions", "CATEGORY_SOCIAL": "Social",
              "CATEGORY_UPDATES": "Updates", "CATEGORY_FORUMS": "Forums"}
BIG_EMAIL_BYTES = 1_000_000  # sizes from here on are highlighted


def metadata_request(service, user_id, msg_id):
    return service.users().messages().get(
        userId=user_id,
        id=msg_id,
        format="metadata",
        metadataHeaders=["Subject", "From", "To", "Date"],
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
        "to": extract_header(headers, "To", ""),
        "labels": detail.get("labelIds", []),
        "size": int(detail.get("sizeEstimate", 0)),
    }


def list_options(in_trash):
    # The Trash and Spam views need this: Gmail leaves spam and trash out of listings otherwise.
    return {"includeSpamTrash": True} if in_trash else {}


def list_candidate_messages(service, user_id, query="", max_results=50, page_token=None, in_trash=False):
    """Return (messages sorted newest first, token for the next older page or None).

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
            **list_options(in_trash),
        ).execute()
        ids.extend(message["id"] for message in response.get("messages", []))
        page_token = response.get("nextPageToken")
        if not page_token:
            break

    details, _ = run_batched(service, ids, lambda msg_id: metadata_request(service, user_id, msg_id))
    detailed_messages = [to_candidate(details[msg_id]) for msg_id in ids if msg_id in details]
    detailed_messages.sort(key=lambda item: item["internalDate"], reverse=True)
    return detailed_messages, page_token


# Tab badges: unread emails (bold) in every view, except Drafts: all drafts (dimmed), as a draft is
# never unread. Without --query, Gmail's exact label counters are used; All mail and Archived (not
# labels) and filtered views are counted from a search.
BADGE_LABELS = {"Inbox": ("INBOX", "unread"), "Starred": ("STARRED", "unread"), "Sent": ("SENT", "unread"),
                "Drafts": ("DRAFT", "total"), "Spam": ("SPAM", "unread"), "Trash": ("TRASH", "unread")}
BADGE_SEARCHED = ["All mail", "Archived"]
BADGE_COUNT_CAP = 1000  # searched counts stop here ("1,000+") to stay quick


def count_messages(service, user_id, query, in_trash=False, cap=BADGE_COUNT_CAP):
    """Exact number of emails matching query, up to cap (Gmail's resultSizeEstimate is too rough)."""
    count, page_token = 0, None
    while count < cap:
        response = service.users().messages().list(
            userId=user_id, q=query, maxResults=500, pageToken=page_token,
            fields="messages/id,nextPageToken", **list_options(in_trash),
        ).execute()
        count += len(response.get("messages", []))
        page_token = response.get("nextPageToken")
        if not page_token:
            return count
    return cap


def badge_text(count):
    return f"{count:,}+" if count >= BADGE_COUNT_CAP else f"{count:,}"


def view_badges(service, user_id, view_queries, filtered):
    """{view name: (text, "unread" | "total")} for the tabs; view_queries maps names to their Gmail search."""
    kinds = {name: kind for name, (_, kind) in BADGE_LABELS.items()}
    kinds.update({name: "unread" for name in BADGE_SEARCHED})
    counts, searched = {}, list(kinds)
    if not filtered:
        labels, _ = run_batched(service, [label for label, _ in BADGE_LABELS.values()],
                                lambda label: service.users().labels().get(userId=user_id, id=label))
        for name, (label, kind) in BADGE_LABELS.items():
            counts[name] = labels.get(label, {}).get("messagesUnread" if kind == "unread" else "messagesTotal")
        searched = BADGE_SEARCHED
    for name in searched:
        query = f"{view_queries[name]} is:unread" if kinds[name] == "unread" else view_queries[name]
        try:
            counts[name] = count_messages(service, user_id, query.strip(), in_trash=name in {"Spam", "Trash"})
        except HttpError as exc:
            debug(f"Could not count {name}: {exc}")
    return {name: (badge_text(count), kinds[name]) for name, count in counts.items() if count}


def estimate_total(service, user_id, query="", in_trash=False):
    """Gmail's (approximate) count of emails matching query; None if unavailable."""
    try:
        response = service.users().messages().list(
            userId=user_id, q=query, maxResults=1, **list_options(in_trash)
        ).execute()
    except HttpError as exc:
        debug(f"Could not estimate the number of emails: {exc}")
        return None
    return response.get("resultSizeEstimate")


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


def header_line(tabs, view, infos, tail, status, columns):
    """Fit the picker's one-line header into columns.

    tabs are (name, counter text or None, style) per view, view the current one; infos the view info
    from longest to shortest; tail the filter and sync / sign-in fragments; status the selection
    text, written at the right edge. tail and status always stay. When the line is full, the info
    gets shorter first, then the other tabs lose their counters, get abbreviated, and finally only
    the current tab is left, then without its counter; the info is cut last.
    """
    width = columns - 1 - sum(cell_len(text) for _, text in tail) - (cell_len(status) + 2 if status else 0)

    def tab_parts(level):
        parts = []
        for position, (name, text, style) in enumerate(tabs):
            if position == view:
                parts.append((style, f" {name} ({text}) " if text and level < 4 else f" {name} "))
            elif level == 0:
                parts.append((style, f" {name} ({text}) " if text else f" {name} "))
            elif level == 1:
                parts.append((style, f" {name} "))
            elif level == 2:
                parts.append((style, f" {name.split()[0][:3]} "))
        return parts

    for level in range(5):
        parts = tab_parts(level)
        room = width - sum(cell_len(text) for _, text in parts)
        if cell_len(infos[-1]) <= room:
            info = next(info for info in infos if cell_len(info) <= room)
            break
    else:
        info = fit(infos[-1], max(0, room)).rstrip()
    parts = parts + [("class:view", info)] + list(tail)
    if status:
        gap = max(2, columns - sum(cell_len(text) for _, text in parts) - cell_len(status) - 1)
        parts += [("", " " * gap), ("class:checked", status)]
    return parts


def sender_name(sender):
    name, address = parseaddr(sender or "")
    return name.strip().strip('"') or address or "—"


def refresh_messages(service, user_id, query, loaded, since=None, page_size=100, in_trash=False):
    """Re-sync loaded emails with Gmail.

    since is the internalDate the loaded range goes down to: older emails are left to load_more. With
    since=None (nothing older to load) the whole query is synced.
    Returns (new messages, ids of loaded messages Gmail no longer lists).
    """
    known = {message["id"] for message in loaded}
    seen, new, page_token = set(), [], None
    while True:
        response = service.users().messages().list(
            userId=user_id, q=query, maxResults=page_size, pageToken=page_token, **list_options(in_trash)
        ).execute()
        ids = [message["id"] for message in response.get("messages", [])]
        seen.update(msg_id for msg_id in ids if msg_id in known)
        crossed = False
        candidates = [msg_id for msg_id in ids if msg_id not in known]
        if since is not None and known and seen == known:
            # Every loaded email is accounted for: unknown ids after the last loaded one are older.
            last = max(position for position, msg_id in enumerate(ids) if msg_id in known)
            candidates = [msg_id for msg_id in ids[:last + 1] if msg_id not in known]
            crossed = True
        details, _ = run_batched(service, candidates, lambda msg_id: metadata_request(service, user_id, msg_id))
        for msg_id in candidates:
            if msg_id not in details:
                continue
            message = to_candidate(details[msg_id])
            if since is None or message["internalDate"] >= since:
                new.append(message)
            else:
                crossed = True  # past the loaded range: the rest comes with load_more
        page_token = response.get("nextPageToken")
        if crossed or not page_token:
            return new, known - seen


DATE_W = 16  # widest compact_date: "2025-08-31 14:05"


def compact_date(internal_date_ms):
    """Mail-client style date: time today, day+month this year, ISO date otherwise."""
    if not internal_date_ms:
        return "—"
    local_date = datetime.fromtimestamp(internal_date_ms / 1000, get_localzone())
    now = datetime.now(local_date.tzinfo)
    if local_date.date() == now.date():
        return local_date.strftime("%H:%M")
    if local_date.year == now.year:
        return f"{local_date.day} {local_date.strftime('%b %H:%M')}"
    return local_date.strftime("%Y-%m-%d %H:%M")


SIZE_W = 6  # widest human_size: "999 KB", "9.9 MB", "123 MB", "1.2 GB"


def human_size(size):
    # Thresholds sit where rounding would add a digit ("10.0 MB"), to stay within SIZE_W.
    if size < 999_500:
        return f"{max(1, size // 1000)} KB"
    if size < 9_950_000:
        return f"{size / 1_000_000:.1f} MB"
    if size < 999_500_000:
        return f"{size / 1_000_000:.0f} MB"
    return f"{size / 1_000_000_000:.1f} GB"


def message_row(message):
    subject = message.get("subject") or "No Subject"
    labels = message.get("labels", [])
    # Like Gmail: for drafts and sent emails the sender is you, so show what matters instead.
    kind = "draft" if "DRAFT" in labels else "sent" if "SENT" in labels else None
    # First recipient; getaddresses keeps a quoted "Doe, John" in one piece.
    to_name, to_address = (getaddresses([message.get("to") or ""]) or [("", "")])[0]
    if kind == "draft":
        sender = "Draft"
    elif kind == "sent":
        is_me = ACCOUNT and to_address.lower() == ACCOUNT.lower()
        sender = "Sent · " + ("me" if is_me else to_name.strip() or to_address or "—")
    else:
        sender = sender_name(message.get("from"))
    category = next((name for label, name in CATEGORIES.items() if label in labels), "")
    user_labels = sorted(USER_LABELS[label] for label in labels if label in USER_LABELS)
    size = message.get("size", 0)
    # (style, text): each kind of tag gets its own color in the list.
    tags = ([("category", category)] if category else []) + [("label", label) for label in user_labels]
    snippet = html.unescape(message.get("snippet") or "")
    return {
        "date": compact_date(message.get("internalDate")),
        "sender": sender,
        "subject": subject,
        "snippet": snippet,
        "attachment": bool(message.get("attachment")),
        "kind": kind,
        "unread": "UNREAD" in labels,
        "starred": "STARRED" in labels,
        "tags": tags,
        "size": human_size(size) if size else "",
        "big": size >= BIG_EMAIL_BYTES,
        # Who the email is from (or to, for sent ones), for "select all from this sender".
        "party": (to_address if kind == "sent" else parseaddr(message.get("from") or "")[1]).lower(),
        "haystack": " ".join([sender, message.get("from", ""), subject, category, *user_labels]).lower(),
    }


def column_widths(rows, total_width):
    """Return (sender, subject, snippet) widths for the space left after fixed columns."""
    fixed = 4 + 5 + DATE_W + 2 + SIZE_W + 2  # cursor + checkbox, star + attachment + unread dot, date, size, gaps
    sender_w = min(max((cell_len(row["sender"]) for row in rows), default=6), 22)
    rest = max(0, total_width - fixed - sender_w - 2 - 1)
    longest_subject = max((cell_len(row["subject"]) for row in rows), default=7)
    subject_w = min(longest_subject, max(20, int(rest * 0.6)), rest)
    snippet_w = rest - subject_w - 2
    return sender_w, subject_w, snippet_w if snippet_w >= 10 else 0


KEY_HELP = [
    ("↑↓ j k", "move (PgUp PgDn Home End too)"),
    ("space", "select / unselect the current email"),
    ("a", "select / unselect all visible emails"),
    ("A", "select / unselect all visible emails from the current email's sender (recipient, for sent ones)"),
    ("z", "sort by size, largest first / back to newest first"),
    ("/", "filter by sender, subject, category or label (e.g. /promo, /draft, /sent, /invoices)"),
    ("Tab", "next view: All mail (everything but spam and trash), Inbox, Archived, Starred, Sent, Drafts, Spam, Trash"),
    ("⇧Tab", "previous view (Shift+Tab)"),
    ("m", "load older emails"),
    ("r", "sign in to Gmail again, in your browser, when the session has expired (shown in the header)"),
    ("p", "preview as PDF, exactly as it would be saved (nothing written to the download folder); marks as read"),
    ("o", "open the current email in Gmail, in your browser; marks as read"),
    ("*", "star / unstar in Gmail"),
    ("!", "mark as unread / read in Gmail (e.g. to keep an email to do after p or o)"),
    ("f", "change the download folder for this session (created if missing)"),
    ("e", "archive: remove from the Inbox, keep in All mail (recoverable: u, or R in Archived)"),
    ("enter", "save PDF + attachments, then move the email to the Gmail trash (recoverable: u)"),
    ("s", "save PDF + attachments, keep the email in Gmail (recoverable: u)"),
    ("R", "Trash: restore (enter and d are off there) · Spam: not spam · Archived: back to the Inbox"),
    ("d", "move to the Gmail trash without saving (recoverable: u, or from Gmail for 30 days)"),
    ("D", "delete permanently, without going through the trash (cannot be undone)"),
    ("T", "empty the whole Gmail trash, not only the selection (cannot be undone)"),
    ("u", "undo the last d, enter, s or e: restores emails from the trash or to the Inbox, removes the files saved"),
    ("?", "show this help"),
    ("q esc", "quit"),
]
PREVIEW_CONFIRM_OVER = 5  # p asks before opening more PDF viewers than this
FOOTER_LINES = 3  # browse / email / delete key groups
KEY_HELP_NOTE = (
    "Actions apply to the selected emails, or to the current one if none is selected.\n"
    "  Archived is not a Gmail folder or label: Gmail archives by removing an email from the Inbox.\n"
    "  This view lists those emails (All mail minus Inbox, Sent and Drafts).\n"
    "  Tab counts: unread emails (white) in every view, except Drafts: all drafts (grey)."
)
# Actions confirmed by typing a word, because they cannot be undone.
TYPED_CONFIRM = {"delete": "delete", "empty_trash": "empty"}


def new_picker_state():
    """Picker state kept across runs, so cursor, filter and selection survive each action."""
    return {"cursor": 0, "top": 0, "query": "", "filtering": False, "selected": set(), "saved": set(),
            "loading": False, "exhausted": True, "confirm": None, "help": False,
            "cursor_id": None, "sort": "date",
            "folder": None,
            "syncing": False, "sync_note": None, "signed_out": False, "signing_in": False}


SYNC_INTERVAL = 60  # seconds between automatic syncs while the list is shown


def pick_messages(messages, load_more=None, state=None, notice=(), undo_label=None, total=None,
                  views=("All mail",), view=0, badges=None, folder="", sync=None, sign_in=None):
    """Interactive multi-select list over messages (extended in place when older emails load).

    Returns (action, chosen messages) where action is "download" (save + trash), "save",
    "trash", "delete" (permanent), "empty_trash", "restore", "not_spam", "archive", "unarchive", "preview", "star", "unread",
    "open", "undo",
    "refresh", "next_view", "prev_view", "folder" or "quit".
    badges maps view names to (count text, "unread" | "total") shown in their tab.
    folder is the download folder f starts editing from; the "folder" action leaves the new one in
    state["folder"].
    sync(loaded) re-reads the view from Gmail in a worker thread and returns {"new", "gone",
    "labels", "badges", "total"}: it runs in the background when the list shows (after every action
    and Tab) and every SYNC_INTERVAL seconds. Results are applied in place (messages, badges).
    When it fails because the Gmail session expired, r runs sign_in() (browser sign-in, in a worker
    thread), then syncs again.
    views are the tab names shown in the header, view the current one; the Trash view swaps
    enter / d (meaningless there) for R restore.
    load_more() runs in a worker thread and returns (older messages sorted newest first, whether even
    older ones remain), optionally followed by a callable run once they are in the list.
    Leaving the list never waits for sync, sign_in or load_more: their result is then dropped.
    notice is a list of formatted-text lines shown under the header (last action result).
    undo_label describes what u would undo (e.g. "trash (3)"), None when there is nothing to undo.
    total is Gmail's estimate of how many emails match the query (shown while more can be loaded).
    """
    from prompt_toolkit.application import Application, get_app
    from prompt_toolkit.filters import Condition
    from prompt_toolkit.key_binding import KeyBindings
    from prompt_toolkit.layout import HSplit, Layout, Window
    from prompt_toolkit.layout.controls import FormattedTextControl
    from prompt_toolkit.layout.dimension import Dimension
    from prompt_toolkit.styles import Style

    rows = [message_row(message) for message in messages]
    in_trash = views[view] == "Trash"
    in_spam = views[view] == "Spam"
    in_archived = views[view] == "Archived"
    state = new_picker_state() if state is None else state
    state.update(filtering=False, loading=False, confirm=None, help=False, folder=None, exhausted=load_more is None)
    notice = list(notice)

    def visible():
        terms = state["query"].lower().split()
        indexes = [i for i, row in enumerate(rows) if all(term in row["haystack"] for term in terms)]
        if state["sort"] == "size":
            indexes.sort(key=lambda index: -messages[index].get("size", 0))
        return indexes

    def size():
        return get_app().output.get_size()

    def list_height():
        # Leave room for the startup line above the picker, its own header/footer and the notice.
        wanted = len(KEY_HELP) + KEY_HELP_NOTE.count("\n") + 2 if state["help"] else len(rows)
        # (header, blank, column titles, list, blank, footer)
        return max(1, min(wanted, size().rows - 7 - (FOOTER_LINES - 1) - len(notice)))

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

    def hidden(ids):
        """How many of ids the current filter hides."""
        return len(ids - {messages[index]["id"] for index in visible()})

    def chosen():
        """Selected ids, or the email under the cursor when nothing is selected."""
        if state["selected"]:
            return set(state["selected"])
        return {current_id()} - {None}

    def render_header():
        indexes = visible()
        count = f"{len(rows)} emails"
        if total and not state["exhausted"] and total > len(rows):
            count = f"{len(rows)} of ~{total:,} emails"
        # Unread for the whole view: the tab's counter when it counts unread, else the loaded emails.
        text, kind = (badges or {}).get(views[view], (None, None))
        unread = text if kind == "unread" else sum(row["unread"] for row in rows)
        full_count = f"{count}, {unread} unread" if unread else count
        tabs = []
        for position, name in enumerate(views):
            text, kind = (badges or {}).get(name, (None, None))
            style = "class:tab.current" if position == view else "class:tab.badge" if kind == "unread" else "class:tab"
            tabs.append((name, text, style))
        order = "largest first" if state["sort"] == "size" else "newest first"
        tail = []
        if state["query"]:
            tail = [("class:dim", f" · {len(indexes)} match "), ("class:accent", state["query"])]
        if state["signing_in"]:
            tail.append(("class:error", " · ↻ sign in to Gmail in your browser…"))
        elif state["signed_out"]:
            tail.append(("class:error", " · ↻ Gmail session expired" + ", r to sign in" * bool(sign_in)))
        elif state["syncing"]:
            tail.append(("class:dim", " · ↻"))
        elif state["sync_note"] and time.monotonic() - state["sync_note"][2] < 10:
            style, text, _ = state["sync_note"]
            tail.append((style, f" · {text}"))
        selected = len(state["selected"])
        status = ""
        if selected:
            status = f"{selected} selected "
            if hidden(state["selected"]):
                status = f"{selected} selected · {hidden(state['selected'])} hidden by the filter "
        # The selection count, the filter and the sync / sign-in state always show: the tabs and
        # the view info make room for them (see header_line).
        infos = (f" · {full_count} · {order}", f" · {full_count}", f" · {count}")
        return header_line(tabs, view, infos, tail, status, size().columns)

    def render_notice():
        parts = []
        for line in notice:
            if parts:
                parts.append(("", "\n"))
            parts += line
        return parts

    def render_help():
        lines = [("class:dim", "  " + KEY_HELP_NOTE), ("", "\n")]
        for key, description in KEY_HELP:
            lines += [("", "\n"), ("class:key", f"  {key:<8}"), ("", description)]
        return lines

    def render_columns():
        """Column titles above the list, aligned with render_list."""
        if state["help"] or not rows:
            return []
        sender_w, subject_w, snippet_w = column_widths(rows, size().columns)
        size_title = ("Size ↓" if state["sort"] == "size" else "Size").rjust(SIZE_W)
        text = (" " * 10 + fit("Date", DATE_W) + "  " + size_title + "  " + fit("From / To", sender_w) + "  "
                + fit("Subject", subject_w))
        if snippet_w:
            text += "  " + fit("Preview", snippet_w)
        return [("class:columns", text)]

    def render_list():
        if state["help"]:
            return render_help()
        indexes = clamp()
        if not indexes:
            return [("class:dim", "   No email matches this filter." if rows else "   No emails here.")]
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
            row_parts = [
                ("class:cursor", " ❯ " if current else "   "),
                mark,
                ("class:star", "★" if row["starred"] else " "),
                ("", "📎" if row["attachment"] else "  "),
                # Unread: a blue dot plus bold sender and subject, like mail clients.
                ("class:unread.dot", "• " if row["unread"] else "  "),
                ("class:dim", fit(row["date"], DATE_W) + "  "),
                ("class:tag.size" if row["big"] else "class:dim", row["size"].rjust(SIZE_W) + "  "),
                *sender_fragments(row, sender_w),
                ("class:unread" if row["unread"] else "", fit(row["subject"], subject_w)),
            ]
            if snippet_w:
                # Size, category and label tags lead the snippet, colored, so they don't need columns.
                row_parts += snippet_fragments(row, snippet_w)
            if current:
                # The cursor row gets a background (not bold, which means unread).
                row_parts = [(f"{style} class:row.current", text) for style, text in row_parts]
            if lines:
                lines.append(("", "\n"))
            lines += row_parts
        return lines

    def hidden_note():
        count = hidden(state["confirm"]["ids"])
        return f" ({count} hidden by the filter)" if count else ""

    def snippet_fragments(row, width):
        fragments, left = [("", "  ")], width
        for kind, text in row["tags"]:
            if left <= 1:
                break
            shown = fit(text, left).rstrip() if cell_len(text) > left else text
            fragments.append((f"class:tag.{kind}", shown))
            left -= cell_len(shown)
            if left >= 3:
                fragments.append(("class:dim", " · "))
                left -= 3
        if left > 0:
            fragments.append(("class:dim", fit(row["snippet"], left)))
        return fragments

    def sender_fragments(row, width):
        text = fit(row["sender"], width) + "  "
        bold = " class:unread" if row["unread"] else ""
        if row["kind"] == "sent":
            # "Sent" colored like a label, the recipient dimmed.
            return [("class:sent" + bold, text[:4]), ("class:dim" + bold, text[4:])]
        return [(("class:draft" if row["kind"] == "draft" else "class:sender") + bold, text)]

    def render_footer():
        rest = []  # footer lines below the first one (key groups only), as lists of fragments
        if state["help"]:
            hint = [("class:dim", " any key to close help")]
        elif state["confirm"] and state["confirm"]["action"] in TYPED_CONFIRM:
            action = state["confirm"]["action"]
            n = len(state["confirm"]["ids"])
            question = (f" Permanently delete {n} email{'s' * (n != 1)}{hidden_note()}?" if action == "delete"
                        else " Permanently delete everything in the Gmail trash?")
            hint = [("class:error", question + " Cannot be undone."),
                    ("class:dim", " Type "), ("class:key", TYPED_CONFIRM[action]), ("class:dim", ": "),
                    ("", state["confirm"]["typed"]), ("class:accent", "▏")]
            rest = [[("class:dim", " enter confirm · esc cancel")]]
        elif state["confirm"]:
            n = len(state["confirm"]["ids"])
            question = (f" Open {n} PDF previews?" if state["confirm"]["action"] == "preview"
                        else f" Move {n} email{'s' * (n != 1)}{hidden_note()} to trash without saving?")
            hint = [("class:warn", question)]
            rest = [[("class:dim", " "), ("class:key", "y"), ("class:dim", " confirm · any other key cancel")]]
        elif state["folder"] is not None:
            hint = [("class:accent", " Download folder: "), ("", state["folder"]), ("class:accent", "▏")]
            rest = [[("class:dim", " enter apply (created if missing) · ctrl+u clear · esc cancel · "
                                   "for this session; --download-path sets it at launch")]]
        elif state["filtering"]:
            hint = [("class:accent", " / "), ("", state["query"]), ("class:accent", "▏"),
                    ("class:dim", "   enter apply · esc clear")]
        else:
            # ↑↓ left out: obvious, and the line is full.
            browse = [("space", "select"), ("a", "all"), ("A", "sender"), ("/", "filter"),
                      ("z", "by date" if state["sort"] == "size" else "by size")]
            if not state["exhausted"]:
                browse.append(("m", "loading…" if state["loading"] else "more"))
            if state["signed_out"] and sign_in is not None:
                browse.append(("r", "signing in…" if state["signing_in"] else "sign in"))
            browse += [("Tab", "views"), ("?", "help"), ("q", "quit")]
            delete = ([] if in_trash else [("d", "trash")]) + [("D", "delete permanently"), ("T", "empty trash")]
            if undo_label:
                delete.append(("u", f"undo {undo_label}"))
            email = [("p", "preview"), ("o", "open in Gmail"), ("*", "star"), ("!", "unread"), ("f", "folder")]
            if in_trash:
                email += [("s", "save+keep"), ("R", "restore")]
            elif in_spam:
                email += [("enter", "save+trash"), ("s", "save+keep"), ("R", "not spam")]
            elif in_archived:
                email += [("enter", "save+trash"), ("s", "save+keep"), ("R", "move to Inbox")]
            else:
                email += [("e", "archive"), ("enter", "save+trash"), ("s", "save+keep")]
            groups = [("browse", browse), ("email", email), ("delete", delete)]
            lines = []
            for name, keys in groups:
                line = [(f"class:group.{name}", f" {name:<7}")]
                for position, (key, label) in enumerate(keys):
                    line += [("class:dim", " · " if position else " "), ("class:key", key), ("class:dim", f" {label}")]
                lines.append(line)
            hint = lines[0]
            rest = lines[1:]
        lines = [hint] + rest
        return [part for position, line in enumerate(lines) for part in ([("", "\n")] if position else []) + line]

    filtering = Condition(lambda: state["filtering"])
    confirming = Condition(lambda: bool(state["confirm"]))
    confirming_yes = Condition(lambda: bool(state["confirm"]) and state["confirm"]["action"] in {"trash", "preview"})
    confirming_typed = Condition(lambda: bool(state["confirm"]) and state["confirm"]["action"] in TYPED_CONFIRM)
    helping = Condition(lambda: state["help"])
    editing_folder = Condition(lambda: state["folder"] is not None)
    browsing = ~filtering & ~confirming & ~helping & ~editing_folder
    bindings = KeyBindings()

    def move(delta):
        state["cursor"] += delta
        clamp()

    def submit(event, action, ids):
        if ids:
            event.app.exit(result=(action, [message for message in messages if message["id"] in ids]))

    bindings.add("up", filter=~confirming & ~helping)(lambda event: move(-1))
    bindings.add("down", filter=~confirming & ~helping)(lambda event: move(1))
    bindings.add("pageup", filter=~confirming & ~helping)(lambda event: move(-list_height()))
    bindings.add("pagedown", filter=~confirming & ~helping)(lambda event: move(list_height()))
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

    @bindings.add("z", filter=browsing)
    def _(event):
        current = current_id()
        state["sort"] = "date" if state["sort"] == "size" else "size"
        # Keep the cursor on the same email in the new order.
        state["cursor"] = next((position for position, index in enumerate(visible())
                                if messages[index]["id"] == current), 0)
        clamp()

    @bindings.add("A", filter=browsing)
    def _(event):
        indexes = visible()
        if not indexes:
            return
        # Same correspondent and same direction: received with received, sent with sent.
        current = rows[indexes[state["cursor"]]]
        party, sent = current["party"], current["kind"] == "sent"
        ids = {messages[index]["id"] for index in indexes
               if party and rows[index]["party"] == party and (rows[index]["kind"] == "sent") == sent}
        if ids <= state["selected"]:
            state["selected"] -= ids
        else:
            state["selected"] |= ids

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

    not_trash = Condition(lambda: not in_trash)
    bindings.add("enter", filter=browsing & not_trash)(lambda event: submit(event, "download", chosen()))

    @bindings.add("enter", filter=browsing & ~not_trash)
    def _(event):
        state["sync_note"] = ("class:error", "enter is off in Trash · s save, R restore", time.monotonic())
    bindings.add("R", filter=browsing & ~not_trash)(lambda event: submit(event, "restore", chosen()))
    bindings.add("R", filter=browsing & Condition(lambda: in_spam))(lambda event: submit(event, "not_spam", chosen()))
    bindings.add("R", filter=browsing & Condition(lambda: in_archived))(lambda event: submit(event, "unarchive", chosen()))
    bindings.add("e", filter=browsing & Condition(lambda: not (in_trash or in_spam or in_archived)))(
        lambda event: submit(event, "archive", chosen()))
    bindings.add("tab", filter=browsing)(lambda event: event.app.exit(result=("next_view", [])))
    bindings.add("s-tab", filter=browsing)(lambda event: event.app.exit(result=("prev_view", [])))
    bindings.add("s", filter=browsing)(lambda event: submit(event, "save", chosen()))
    @bindings.add("p", filter=browsing)
    def _(event):
        # Each preview opens a PDF viewer window: ask before opening many at once.
        if len(chosen()) > PREVIEW_CONFIRM_OVER:
            ask_confirm("preview")
        else:
            submit(event, "preview", chosen())

    def ask_confirm(action):
        ids = set() if action == "empty_trash" else chosen()
        state["confirm"] = {"action": action, "ids": ids, "typed": ""} if ids or action == "empty_trash" else None

    bindings.add("d", filter=browsing & not_trash)(lambda event: ask_confirm("trash"))
    bindings.add("D", filter=browsing)(lambda event: ask_confirm("delete"))
    bindings.add("T", filter=browsing)(lambda event: ask_confirm("empty_trash"))

    @bindings.add("?", filter=browsing)
    def _(event):
        state["help"] = True

    @bindings.add("<any>", filter=helping)
    def _(event):
        state["help"] = False

    bindings.add("y", filter=confirming_yes)(
        lambda event: submit(event, state["confirm"]["action"], state["confirm"]["ids"]))

    @bindings.add("<any>", filter=confirming_yes)
    @bindings.add("escape", filter=confirming_typed)
    def _(event):
        state["confirm"] = None

    @bindings.add("enter", filter=confirming_typed)
    def _(event):
        action = state["confirm"]["action"]
        if state["confirm"]["typed"] != TYPED_CONFIRM[action]:
            state["confirm"] = None
        elif action == "empty_trash":
            event.app.exit(result=("empty_trash", []))
        else:
            submit(event, action, state["confirm"]["ids"])

    @bindings.add("backspace", filter=confirming_typed)
    def _(event):
        state["confirm"]["typed"] = state["confirm"]["typed"][:-1]

    @bindings.add("<any>", filter=confirming_typed)
    def _(event):
        if event.data.isprintable():
            state["confirm"]["typed"] += event.data

    bindings.add("*", filter=browsing)(lambda event: submit(event, "star", chosen()))
    bindings.add("!", filter=browsing)(lambda event: submit(event, "unread", chosen()))
    bindings.add("o", filter=browsing)(lambda event: submit(event, "open", {current_id()} - {None}))

    def apply_sync(result):
        """Merge a sync result into the list, keeping the cursor on the same email."""
        nonlocal total
        current = current_id()
        gone, fresh = result["gone"], result["labels"]
        updated = 0
        for message in messages:
            labels = fresh.get(message["id"])
            if labels is not None and set(labels) != set(message.get("labels", [])):
                message["labels"] = labels
                updated += 1
        known = {message["id"] for message in messages}
        new = [message for message in result["new"] if message["id"] not in known]
        messages[:] = [message for message in messages if message["id"] not in gone] + new
        messages.sort(key=lambda message: message["internalDate"], reverse=True)
        rows[:] = [message_row(message) for message in messages]
        state["selected"] -= gone
        if badges is not None:
            badges.clear()
            badges.update(result["badges"])
        total = result["total"]
        if current:
            state["cursor"] = next((position for position, index in enumerate(visible())
                                    if messages[index]["id"] == current), state["cursor"])
        clamp()
        parts = [f"{len(new)} new"] * bool(new) + [f"{len(gone)} gone"] * bool(gone)
        parts += [f"{updated} updated"] * bool(updated)
        state["sync_note"] = ("class:checked", "↻ " + ", ".join(parts), time.monotonic()) if parts else None

    async def run_sync(app):
        if sync is None or state["syncing"]:
            return
        state["syncing"] = True
        app.invalidate()
        snapshot = [{"id": message["id"], "internalDate": message["internalDate"],
                     "labels": list(message.get("labels", []))} for message in messages]
        try:
            result = await in_background(sync, snapshot)
        except RefreshError as exc:
            debug(f"Sync failed: {exc}")
            state["signed_out"] = True
        except Exception as exc:
            debug(f"Sync failed: {exc}")
            state["sync_note"] = ("class:error", "↻ sync failed, retrying", time.monotonic())
        else:
            state["signed_out"] = False
            apply_sync(result)
        finally:
            state["syncing"] = False
            app.invalidate()

    async def keep_in_sync(app):
        # Right away (catches what changed elsewhere since the last look), then every SYNC_INTERVAL.
        while True:
            await run_sync(app)
            await asyncio.sleep(SYNC_INTERVAL)

    async def run_sign_in(app):
        state["signing_in"] = True
        app.invalidate()
        try:
            await in_background(sign_in)
        except Exception as exc:
            debug(f"Sign-in failed: {exc}")
            state["sync_note"] = ("class:error", "↻ sign-in failed, r to try again", time.monotonic())
        else:
            state["signed_out"] = False
        finally:
            state["signing_in"] = False
            app.invalidate()
        if not state["signed_out"]:
            await run_sync(app)

    @bindings.add("r", filter=browsing & Condition(
        lambda: sign_in is not None and state["signed_out"] and not state["signing_in"]))
    def _(event):
        event.app.create_background_task(run_sign_in(event.app))

    @bindings.add("u", filter=browsing & Condition(lambda: bool(undo_label)))
    def _(event):
        event.app.exit(result=("undo", []))

    @bindings.add("m", filter=browsing)
    def _(event):
        if state["loading"] or state["exhausted"]:
            return
        state["loading"] = True

        async def load():
            try:
                older, more, *loaded = await in_background(load_more)
            except Exception as exc:
                debug(f"Loading more failed: {exc}")
                if isinstance(exc, RefreshError):
                    state["signed_out"] = True
                else:
                    state["sync_note"] = ("class:error", "m loading failed, m to try again", time.monotonic())
            else:
                state["exhausted"] = not more
                # Older emails go at the bottom, so the cursor stays where it is.
                messages.extend(older)
                rows.extend(message_row(message) for message in older)
                for done in loaded:
                    done()
            finally:
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

    @bindings.add("f", filter=browsing)
    def _(event):
        state["folder"] = folder

    @bindings.add("enter", filter=editing_folder)
    def _(event):
        event.app.exit(result=("folder", []))

    @bindings.add("escape", filter=editing_folder)
    def _(event):
        state["folder"] = None

    @bindings.add("backspace", filter=editing_folder)
    def _(event):
        state["folder"] = state["folder"][:-1]

    @bindings.add("c-u", filter=editing_folder)
    def _(event):
        state["folder"] = ""

    @bindings.add("<any>", filter=editing_folder)
    def _(event):
        if event.data.isprintable():
            state["folder"] += event.data

    # Grays are absolute, not ANSI bright black: some palettes (Solarized dark) make that the background.
    # The cursor row has an absolute background, so it sets its text color too, readable on light themes.
    style = Style.from_dict({
        "title": "bold",
        "columns": "fg:#8a8a8a underline",
        "tab": "fg:#8a8a8a",
        # Current view: its tab filled with the view color, the header info written in it.
        "tab.current": f"reverse bold fg:{VIEW_COLORS.get(views[view], 'ansicyan')}",
        "view": f"fg:{VIEW_COLORS.get(views[view], 'ansicyan')}",
        "tab.badge": "fg:default bold",
        "dim": "fg:#8a8a8a",
        "accent": "fg:ansicyan bold",
        "cursor": "fg:ansicyan bold",
        "checked": "fg:ansigreen bold",
        "saved": "fg:ansigreen",
        "error": "fg:ansired bold",
        "sender": "fg:ansicyan",
        "draft": "fg:ansired",
        "sent": "fg:ansimagenta",
        "unread": "bold",
        "star": "fg:ansiyellow",
        "tag.size": "fg:ansiyellow",
        "tag.category": "fg:ansiblue",
        "tag.label": "fg:ansigreen",
        "row.current": "fg:#e4e4e4 bg:#303030",
        "unread.dot": "fg:ansiblue bold",
        "key": "bold",
        "group.browse": "fg:ansicyan bold",
        "group.email": "fg:ansigreen bold",
        "group.delete": "fg:ansired bold",
        "warn": "fg:ansiyellow bold",
    })
    windows = [Window(FormattedTextControl(render_header), height=1)]
    if notice:
        windows.append(Window(FormattedTextControl(render_notice), height=len(notice)))
    windows += [
        Window(height=1),
        Window(FormattedTextControl(render_columns), height=1),
        Window(FormattedTextControl(render_list), height=lambda: Dimension.exact(list_height())),
        Window(height=1),
        Window(FormattedTextControl(render_footer), height=FOOTER_LINES),
    ]
    app = Application(layout=Layout(HSplit(windows)), key_bindings=bindings, style=style, erase_when_done=True)
    app.ttimeoutlen = 0.05
    # Emails may be added above the cursor between runs (refresh): put it back on the same email.
    positions = [position for position, index in enumerate(visible()) if messages[index]["id"] == state["cursor_id"]]
    if positions:
        state["cursor"] = positions[0]
    discard_pending_keys(app.input)
    # Own thread: Playwright's sync API keeps an event loop running in the main one between actions.
    result = app.run(in_thread=True, pre_run=lambda: sync and app.create_background_task(keep_in_sync(app))) \
        or ("quit", [])
    state["cursor_id"] = current_id()
    return result


def print_message_line(mark, message, detail="", sender_w=22):
    row = message_row(message)
    width = console.width
    detail_w = max(20, cell_len(detail))
    subject_w = max(10, width - 4 - (DATE_W + 2) - sender_w - 2 - detail_w - 3)
    console.print(
        f" {mark}  [dim]{escape(fit(row['date'], DATE_W))}[/]  "
        f"[{ {'draft': 'red', 'sent': 'magenta'}.get(row['kind'], 'cyan') }]{escape(fit(row['sender'], sender_w))}[/]  "
        f"{escape(fit(row['subject'], subject_w))}  [dim]{escape(fit(detail, width - 4 - (DATE_W + 2) - sender_w - 2 - subject_w - 3))}[/]"
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


def ask_user_to_select_messages(messages, load_more=None, state=None, notice=(), undo_label=None, total=None,
                                views=("All mail",), view=0, badges=None, folder="", sync=None, sign_in=None):
    """Pick emails interactively, or by typed numbers when not attached to a terminal.

    Returns (action, messages); see pick_messages for the actions.
    """
    if sys.stdin.isatty() and sys.stdout.isatty():
        return pick_messages(messages, load_more, state, notice, undo_label, total, views, view, badges, folder, sync,
                             sign_in)
    if not messages:
        return "quit", []

    for line in notice:
        # Key hints only make sense in the interactive picker.
        console.print(escape("".join(text for style, text in line if "keyhint" not in style)))
    sender_w = min(max(cell_len(message_row(m)["sender"]) for m in messages), 22)
    num_w = len(str(len(messages)))
    for number, message in enumerate(messages, start=1):
        row = message_row(message)
        subject_w = max(10, console.width - num_w - DATE_W - 8 - sender_w)
        console.print(escape(f" {number:>{num_w}}  {fit(row['date'], DATE_W)}  {fit(row['sender'], sender_w)}  {fit(row['subject'], subject_w)}"))
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


def preview_messages(service, user_id, messages, browser, preview_dir):
    """Render emails exactly as a download would (attachments not written) and open each in the PDF viewer.

    Returns {id: error text} for the ones that failed.
    """
    failed = {}
    with console.status("[dim]Rendering preview…[/]") as status:
        for number, message in enumerate(messages, start=1):
            counter = f" {number}/{len(messages)}" if len(messages) > 1 else ""

            def on_step(step):
                status.update(f"[dim]Preview{counter} · {escape(step)}…[/]")

            try:
                result = save_email_and_attachments(
                    service, user_id, message["id"], preview_dir, browser, on_step, save_attachments=False
                )
            except Exception as exc:
                failed[message["id"]] = str(exc)
            else:
                # Open each one as soon as it is ready instead of waiting for the whole selection.
                open_quietly(os.path.join(preview_dir, result["pdf"]))
    return failed


def save_messages(service, user_id, messages, save_dir, browser, trash_after):
    """Save emails as PDFs + attachments, then (optionally) trash the saved ones in one batch.

    Returns (saved messages, attachment count, {id: error text}, {id: written file paths}).
    """
    sender_w = min(max(cell_len(message_row(m)["sender"]) for m in messages), 22)
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
    files = {msg_id: result["files"] for msg_id, result in results.items()}
    return saved, sum(result["attachments"] for result in results.values()), failed, files


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
        prog="savegmail",
        description=(
            "Browse Gmail in the terminal: save emails as PDFs (with attachments), move them\n"
            "to the trash, or delete them permanently. The list comes back after each action."
        ),
        epilog="keys (in the list):\n" + "\n".join(
            [f"  {key:<8}{description}" for key, description in KEY_HELP] + ["", "  " + KEY_HELP_NOTE]
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--query",
        default="",
        help="Gmail search query (default: all emails), e.g. 'newer_than:30d', 'from:foo', 'has:attachment'.",
    )
    parser.add_argument(
        "--max",
        type=int,
        default=50,
        metavar="N",
        help="Emails loaded per page (default: 50); press m in the list for older ones.",
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
        help="Permanently delete everything in the Gmail trash, after confirmation, then exit.",
    )
    parser.add_argument(
        "--headed",
        action="store_true",
        help="Render PDFs in a visible Chromium window (fallback if an email captures badly headless).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show sign-in, token, Chromium, MIME and PDF rendering details.",
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
    playwright = browser = preview_dir = None

    def browser_alive():
        """Whether the kept Chromium still answers; is_connected() alone lags behind a crash."""
        if not browser.is_connected():
            return False
        try:
            browser.new_browser_cdp_session().detach()
            return True
        except PlaywrightError:
            return False

    def get_browser():
        """Start Chromium on first use and keep it; start it again if it was closed or crashed."""
        nonlocal playwright, browser
        if browser is None or not browser_alive():
            playwright = playwright or sync_playwright().start()
            with console.status("[dim]Preparing Chromium…[/]"):
                browser = launch_browser(playwright, headed=args.headed)
        return browser

    try:
        service = build("gmail", "v1", credentials=creds)
        user_id = "me"
        save_dir = os.path.expanduser(args.download_path)
        os.makedirs(save_dir, exist_ok=True)
        shown_dir = save_dir.replace(os.path.expanduser("~"), "~", 1)

        account = service.users().getProfile(userId=user_id).execute().get("emailAddress", user_id)
        def make_banner():
            return (
                f" [bold]savegmail[/]  [dim]·[/]  {escape(account)}  [dim]·  query:[/] "
                f"{escape(args.query) if args.query else '[dim](all)[/]'}  [dim]·  →[/] {escape(shown_dir)}\n"
            )

        banner = make_banner()
        console.print(banner)
        global ACCOUNT, USER_LABELS
        ACCOUNT = account
        USER_LABELS = user_labels(service, user_id)

        def make_view(name, view_filter):
            query = " ".join(part for part in [f"({args.query})" if args.query else "", view_filter] if part)
            return {"name": name, "query": query, "in_trash": name in {"Trash", "Spam"}, "messages": [], "more": False,
                    "floor": None, "total": None, "state": new_picker_state(), "loaded": False, "stale": False}

        views = [make_view(name, view_filter) for name, view_filter in VIEWS]
        current = 0

        def load_view(view):
            with console.status(f"[dim]Fetching {view['name']}…[/]"):
                loaded, token = list_candidate_messages(
                    service, user_id, query=view["query"], max_results=args.max, in_trash=view["in_trash"]
                )
                view["total"] = estimate_total(service, user_id, view["query"], view["in_trash"]) if token else None
            view["messages"][:] = loaded
            # m asks Gmail for emails older than the oldest one loaded so far: unlike page tokens, this
            # stays right after refreshes and after emails were trashed during the session.
            view["floor"] = min((message["internalDate"] for message in loaded), default=None)
            view["more"] = token is not None
            view["loaded"], view["stale"] = True, False

        def load_more_for(view):
            # Runs in a worker thread the list may abandon: it uses the sync connection (the main one
            # is used meanwhile), and the view only moves its floor once the emails are in the list.
            def load_more():
                with sync_lock:
                    before = f"before:{view['floor'] // 1000 + 1}"  # Gmail dates are in seconds; duplicates dropped
                    older, token = list_candidate_messages(
                        sync_service, user_id, query=f"{view['query']} {before}".strip(), max_results=args.max,
                        in_trash=view["in_trash"],
                    )
                known = {message["id"] for message in view["messages"]}
                older = [message for message in older if message["id"] not in known]

                def loaded():
                    if older:
                        view["floor"] = min(view["floor"], min(message["internalDate"] for message in older))
                    view["more"] = token is not None
                return older, token is not None, loaded
            return load_more

        def drop(view, ids):
            messages = view["messages"]
            before = len(messages)
            messages[:] = [message for message in messages if message["id"] not in ids]
            view["state"]["selected"] -= ids
            if view["total"]:
                view["total"] = max(0, view["total"] - (before - len(messages)))

        def refresh_view(view, quiet=False):
            """Re-sync a view with Gmail; returns its notice lines (none if quiet and nothing changed)."""
            try:
                with console.status("[dim]Checking Gmail…[/]"):
                    new, removed = refresh_messages(
                        service, user_id, view["query"], view["messages"],
                        since=view["floor"] if view["more"] else None, in_trash=view["in_trash"],
                    )
                    if view["more"]:
                        view["total"] = estimate_total(service, user_id, view["query"], view["in_trash"])
            except GMAIL_ERRORS as exc:
                return [[("class:error", " ✗ "), ("", "Refresh failed"), ("class:dim", " · " + fit(str(exc), 80).rstrip())]]
            drop(view, removed)
            try:
                # Read / unread, stars… changed in Gmail meanwhile (web, phone, o).
                updated = refresh_labels(service, user_id, view["messages"])
            except GMAIL_ERRORS as exc:
                debug(f"Could not refresh labels: {exc}")
                updated = 0
            known = {message["id"] for message in view["messages"]}
            view["messages"].extend(message for message in new if message["id"] not in known)
            view["messages"].sort(key=lambda message: message["internalDate"], reverse=True)
            if view["floor"] is None and view["messages"]:
                view["floor"] = min(message["internalDate"] for message in view["messages"])
            view["stale"] = False
            parts = []
            if new:
                parts.append(f"{len(new)} new")
            if removed:
                parts.append(f"{len(removed)} gone (deleted or moved in Gmail)")
            if updated:
                parts.append(f"{updated} updated (read, starred or labeled in Gmail)")
            if quiet and not parts:
                return []
            return [[("class:checked", " ↻ "), ("", " · ".join(parts) or "Up to date")]]

        # The background sync runs in a worker thread: it gets its own Gmail connection (the client
        # is not thread-safe) and only reads, the list applies its result. The list may abandon it
        # (Tab, q, an action) while it runs, so the next one waits for it on the lock.
        sync_service = build("gmail", "v1", credentials=creds)
        sync_lock = threading.Lock()
        view_queries = {view["name"]: view["query"] for view in views}

        def reload_session():
            """Pick up a sign-in done since launch (token.json rewritten); True if the session changed.

            The credentials are updated in place, so the main Gmail connection gets them too.
            """
            try:
                fresh = Credentials.from_authorized_user_file(TOKEN_PATH, SCOPES)
            except (OSError, ValueError):
                return False
            if not fresh.refresh_token or fresh.refresh_token == creds.refresh_token:
                return False
            adopt(fresh)
            return True

        def adopt(fresh):
            creds.token, creds._refresh_token, creds.expiry = fresh.token, fresh.refresh_token, fresh.expiry

        def sign_in_again():
            adopt(sign_in_quietly())

        def sync_for(view):
            def sync(loaded):
                with sync_lock:
                    try:
                        return sync_once(loaded)
                    except RefreshError:
                        if not reload_session():
                            raise
                        return sync_once(loaded)

            def sync_once(loaded):
                new, gone = refresh_messages(
                    sync_service, user_id, view["query"], loaded,
                    since=view["floor"] if view["more"] else None, in_trash=view["in_trash"],
                )
                labels = current_labels(sync_service, user_id, [message["id"] for message in loaded
                                                                if message["id"] not in gone])
                total = view["total"]
                if view["more"]:
                    total = estimate_total(sync_service, user_id, view["query"], view["in_trash"])
                    view["total"] = total
                return {"new": new, "gone": gone, "labels": labels, "total": total,
                        "badges": view_badges(sync_service, user_id, view_queries, bool(args.query))}
            return sync

        badges = {}  # tab counters, filled and kept current by the background sync
        load_view(views[current])
        notice = []
        # Last reversible action (d, enter, s or e): its key-help name, emails to restore from the trash,
        # files to remove, emails to put back in the Inbox.
        undo = None

        def undo_text(undo):
            if not undo:
                return None
            count = len({message["id"] for message in undo["trashed"] + undo.get("archived", [])} | set(undo["files"]))
            return f"{undo['label']} ({count})"

        def forget_deleted(undo, deleted):
            """The undo left once emails are permanently deleted (None if nothing is left).

            They can't be restored or put back in the Inbox, and their saved files are now the only copy,
            so keep them; the rest of the undo (other emails, an e) still applies.
            """
            if not undo:
                return None
            trashed = [message for message in undo["trashed"] if message["id"] not in deleted]
            archived = [message for message in undo.get("archived", []) if message["id"] not in deleted]
            kept = {msg_id: files for msg_id, files in undo["files"].items() if msg_id not in deleted}
            return ({"label": undo["label"], "trashed": trashed, "archived": archived, "files": kept}
                    if trashed or archived or kept else None)

        def sign_out_if_expired(*errors):
            """An expired or revoked session: every view offers r to sign in again."""
            if any(isinstance(error, RefreshError) for error in errors):
                for each in views:
                    each["state"]["signed_out"] = True

        totals = {"saved": 0, "trashed": 0, "deleted": 0}
        # Back to the list after every action, until the user quits.
        while True:
            view = views[current]
            messages, state = view["messages"], view["state"]
            action, chosen = ask_user_to_select_messages(
                messages, load_more_for(view) if view["more"] else None, state, notice, undo_text(undo),
                view["total"], [view["name"] for view in views], current, badges, shown_dir, sync_for(view),
                sign_in_again,
            )
            if action == "quit" or (
                action not in {"undo", "empty_trash", "refresh", "next_view", "prev_view", "folder"} and not chosen
            ):
                break
            ids = {message["id"] for message in chosen}

            if action == "folder":
                wanted = os.path.expanduser((state["folder"] or "").strip())
                try:
                    if not wanted:
                        raise OSError("empty path")
                    os.makedirs(wanted, exist_ok=True)
                except OSError as exc:
                    notice = [[("class:error", " ✗ "), ("", "Could not use that folder"),
                               ("class:dim", " · " + fit(str(exc), 80).rstrip())]]
                else:
                    save_dir = os.path.abspath(wanted)
                    shown_dir = save_dir.replace(os.path.expanduser("~"), "~", 1)
                    banner = make_banner()
                    notice = [[("class:checked", " ✓ "), ("", "Download folder: "), ("class:dim", shown_dir)]]
                console.clear()
                console.print(banner)
                continue

            try:
                if action in {"next_view", "prev_view"}:
                    current = (current + (1 if action == "next_view" else -1)) % len(views)
                    view = views[current]
                    notice = []
                    if not view["loaded"]:
                        load_view(view)

                elif action == "preview":
                    # Previews live in a session temp dir (never in the download folder), removed on quit.
                    preview_dir = preview_dir or tempfile.mkdtemp(prefix="savegmail-preview-")
                    failed = preview_messages(service, user_id, chosen, get_browser(), preview_dir)
                    mark_read(service, user_id, [message for message in chosen if message["id"] not in failed])
                    if failed:
                        notice = [[("class:error", " ✗ "), ("", f"Preview failed for {plural(len(failed), 'email')}")]]
                        notice += failure_notice(chosen, failed)

                elif action == "undo":
                    errors = {}
                    if undo["trashed"]:
                        with console.status("[dim]Restoring from trash…[/]"):
                            errors = untrash_messages(service, user_id, [message["id"] for message in undo["trashed"]])
                    restored = [message for message in undo["trashed"] if message["id"] not in errors]
                    totals["trashed"] -= len(restored)
                    # Emails still stuck in the trash keep their files, so a retry of u stays consistent.
                    unsaved = {msg_id: files for msg_id, files in undo["files"].items() if msg_id not in errors}
                    removed = [path for files in unsaved.values() for path in files]
                    remove_files(removed)
                    totals["saved"] -= len(unsaved)
                    for each in views:
                        each["state"]["saved"] -= set(unsaved)
                    unarchived = []
                    if undo.get("archived"):
                        done, error = batch_outcome(lambda: modify_labels(
                            service, user_id, [message["id"] for message in undo["archived"]], add=["INBOX"]), GMAIL_ERRORS)
                        unarchived = [message for message in undo["archived"] if done is None or message["id"] in done]
                        errors.update({message["id"]: error for message in undo["archived"]
                                       if done is not None and message["id"] not in done})
                    if restored or unarchived:
                        # Emails go back to whichever views they belong to.
                        refresh_view(view)
                    parts = []
                    if restored:
                        parts.append(f"{plural(len(restored), 'email')} restored from trash")
                    if unarchived:
                        parts.append(f"{plural(len(unarchived), 'email')} back in the Inbox")
                    if removed:
                        parts.append(f"{plural(len(removed), 'file')} removed")
                    notice = [[("class:checked", " ↶ "), ("", " · ".join(parts) or "Nothing undone")]]
                    notice += failure_notice(undo["trashed"] + undo.get("archived", []),
                                             {msg_id: str(exc) for msg_id, exc in errors.items()})
                    sign_out_if_expired(*errors.values())
                    stuck = [message for message in undo["trashed"] if message["id"] in errors]
                    stuck_archived = [message for message in undo.get("archived", []) if message["id"] in errors]
                    undo = {"label": undo["label"], "trashed": stuck, "archived": stuck_archived,
                            "files": {msg_id: undo["files"][msg_id] for msg_id in errors if msg_id in undo["files"]}
                            } if stuck or stuck_archived else None

                elif action in {"archive", "not_spam", "unarchive"}:
                    # Archive leaves the Inbox; "not spam" and unarchive go back to it, like in Gmail.
                    add, remove = {"archive": ([], ["INBOX"]), "not_spam": (["INBOX"], ["SPAM"]),
                                   "unarchive": (["INBOX"], [])}[action]
                    # Gmail takes 1000 emails per call: a failed call can follow ones that went through.
                    done, error = batch_outcome(lambda: modify_labels(service, user_id, list(ids), add=add, remove=remove),
                                                GMAIL_ERRORS)
                    moved = [message for message in chosen if done is None or message["id"] in done]
                    notice = []
                    if moved:
                        # u only puts back the emails that were in the Inbox (not sent or already archived ones).
                        left_inbox = [message for message in moved if "INBOX" in message.get("labels", [])]
                        for message in moved:
                            message["labels"] = [label for label in message.get("labels", []) if label not in remove] + add
                        if view["name"] in {"Inbox", "Spam", "Archived"}:
                            drop(view, {message["id"] for message in moved})
                        if action == "archive":
                            notice = [[("class:checked", " ✓ "), ("", f"{plural(len(moved), 'email')} archived")]]
                            if left_inbox:
                                undo = {"label": "archive", "trashed": [], "files": {}, "archived": left_inbox}
                                notice[0].append(("class:dim class:keyhint", " · u undo"))
                        else:
                            notice = [[("class:checked", " ✓ "), ("", f"{plural(len(moved), 'email')} moved to the Inbox")]]
                    sign_out_if_expired(error)
                    if error is not None:
                        notice.append([("class:error", " ✗ "),
                                       ("", f"Could not {'archive' if action == 'archive' else 'move'} "
                                            f"{plural(len(chosen) - len(moved), 'email')}"),
                                       ("class:dim", " · " + fit(str(error), 80).rstrip())])

                elif action == "restore":
                    with console.status("[dim]Restoring from trash…[/]"):
                        errors = untrash_messages(service, user_id, list(ids))
                    restored = [message for message in chosen if message["id"] not in errors]
                    drop(view, {message["id"] for message in restored})
                    notice = [[("class:checked", " ↶ "), ("", f"{plural(len(restored), 'email')} restored from trash")]
                              if restored else [("class:error", " ✗ "), ("", "Nothing restored from trash")]]
                    notice += failure_notice(chosen, {msg_id: str(exc) for msg_id, exc in errors.items()})
                    sign_out_if_expired(*errors.values())

                elif action == "trash":
                    with console.status("[dim]Moving to trash…[/]"):
                        errors = trash_messages(service, user_id, list(ids))
                    trashed = [message for message in chosen if message["id"] not in errors]
                    drop(view, {message["id"] for message in trashed})
                    if trashed:
                        undo = {"label": "trash", "trashed": trashed, "files": {}}
                    totals["trashed"] += len(trashed)
                    notice = [[("class:checked", " ✓ "), ("", f"{plural(len(trashed), 'email')} moved to trash (not saved)"),
                               ("class:dim class:keyhint", " · u undo")]
                              if trashed else [("class:error", " ✗ "), ("", "Nothing moved to trash")]]
                    notice += failure_notice(chosen, {msg_id: str(exc) for msg_id, exc in errors.items()})
                    sign_out_if_expired(*errors.values())

                elif action == "open":
                    open_quietly(gmail_url(account, chosen[0]["id"]))
                    # Gmail marks it read once shown; do it now so the list and counters agree right away.
                    mark_read(service, user_id, chosen)

                elif action == "unread":
                    # Like star: mark them all unread, unless they all already are, then mark them read.
                    unread = not all("UNREAD" in message.get("labels", []) for message in chosen)
                    done, error = batch_outcome(lambda: modify_labels(
                        service, user_id, list(ids), **{"add" if unread else "remove": ["UNREAD"]}), GMAIL_ERRORS)
                    changed = [message for message in chosen if done is None or message["id"] in done]
                    for message in changed:
                        labels = [label for label in message.get("labels", []) if label != "UNREAD"]
                        message["labels"] = labels + ["UNREAD"] if unread else labels
                    notice = [[("class:checked", " ● " if unread else " ○ "),
                               ("", f"{plural(len(changed), 'email')} marked as {'unread' if unread else 'read'}")]
                              ] if changed else []
                    sign_out_if_expired(error)
                    if error is not None:
                        notice.append([("class:error", " ✗ "), ("", "Could not change the read state" + (
                            f" of {plural(len(chosen) - len(changed), 'email')}" if changed else "")),
                                       ("class:dim", " · " + fit(str(error), 80).rstrip())])

                elif action == "star":
                    # Like Gmail: star them all, unless they all are already starred.
                    star = not all("STARRED" in message.get("labels", []) for message in chosen)
                    done, error = batch_outcome(lambda: modify_labels(
                        service, user_id, list(ids), **{"add" if star else "remove": ["STARRED"]}), GMAIL_ERRORS)
                    changed = [message for message in chosen if done is None or message["id"] in done]
                    for message in changed:
                        labels = [label for label in message.get("labels", []) if label != "STARRED"]
                        message["labels"] = labels + ["STARRED"] if star else labels
                    notice = [[("class:star", " ★ " if star else " ☆ "),
                               ("", f"{plural(len(changed), 'email')} {'starred' if star else 'unstarred'}")]
                              ] if changed else []
                    sign_out_if_expired(error)
                    if error is not None:
                        notice.append([("class:error", " ✗ "), ("", "Could not change the star" + (
                            f" of {plural(len(chosen) - len(changed), 'email')}" if changed else "")),
                                       ("class:dim", " · " + fit(str(error), 80).rstrip())])

                elif action == "empty_trash":
                    trash_ids = []

                    def empty():
                        trash_ids.extend(list_trash_ids(service, user_id))
                        delete_messages(service, user_id, trash_ids)
                    with console.status("[dim]Emptying trash…[/]"):
                        deleted, error = batch_outcome(empty)
                    notice = []
                    if deleted is None:
                        # Everything in the trash is gone for good, including emails saved with s from the Trash.
                        deleted = set(trash_ids) | ({message["id"] for message in undo["trashed"]} if undo else set())
                        if view["in_trash"]:
                            drop(view, {message["id"] for message in messages})
                        notice = [[("class:checked", " ✓ "),
                                   ("", f"Trash emptied · {plural(len(trash_ids), 'email')} permanently deleted")]]
                    elif deleted:
                        # Gmail takes 1000 emails per call: the ones before the failed call are gone.
                        if view["in_trash"]:
                            drop(view, deleted)
                        notice = [[("class:checked", " ✓ "), ("", f"{plural(len(deleted), 'email')} permanently deleted")]]
                    if deleted:
                        undo = forget_deleted(undo, deleted)
                        totals["deleted"] += len(deleted & set(trash_ids))
                    if error is not None:
                        notice.append([("class:error", " ✗ "), ("", "Could not empty the trash"),
                                       ("class:dim", " · " + fit(str(error), 80).rstrip())])

                elif action == "delete":
                    with console.status("[dim]Deleting…[/]"):
                        deleted, error = batch_outcome(lambda: delete_messages(service, user_id, list(ids)))
                    # Each call of 1000 is all-or-nothing, not the whole: the ones before a failed call are gone.
                    deleted = ids if deleted is None else deleted
                    notice = []
                    if deleted:
                        drop(view, deleted)
                        totals["deleted"] += len(deleted)
                        undo = forget_deleted(undo, deleted)
                        notice = [[("class:checked", " ✓ "), ("", f"{plural(len(deleted), 'email')} permanently deleted")]]
                    if error is not None:
                        notice.append([("class:error", " ✗ "), ("", f"Could not delete {plural(len(ids) - len(deleted), 'email')}"),
                                       ("class:dim", " · " + fit(str(error), 80).rstrip())])

                else:
                    trash_after = action == "download"
                    saved, attachments, failed, files = save_messages(service, user_id, chosen, save_dir, get_browser(), trash_after)
                    saved_ids = {message["id"] for message in saved}
                    totals["saved"] += len(saved)
                    summary = f"{plural(len(saved), 'PDF')} · {plural(attachments, 'attachment')}"
                    if trash_after:
                        drop(view, saved_ids)
                        if saved:
                            undo = {"label": "save+trash", "trashed": saved, "files": files}
                        totals["trashed"] += len(saved)
                        summary += " · moved to trash"
                    else:
                        state["selected"] -= saved_ids
                        state["saved"] |= saved_ids
                        if saved:
                            undo = {"label": "save+keep", "trashed": [], "files": files}
                        summary += " · kept in Gmail"
                    notice = [[("class:checked", " ✓ "), ("", summary), ("class:dim", f" → {shown_dir}"),
                               ("class:dim class:keyhint", " · u undo")]
                              if saved else [("class:error", " ✗ "), ("", "Nothing saved")]]
                    notice += failure_notice(chosen, failed)
            except GMAIL_ERRORS as exc:
                # Session expired or Gmail unreachable midway: back to the list, the undo kept as it was.
                debug(f"Gmail request failed: {exc}")
                sign_out_if_expired(exc)
                if isinstance(exc, RefreshError):
                    notice = [[("class:error", " ✗ "), ("", "Gmail session expired"),
                               ("class:dim class:keyhint", " · r to sign in again")]]
                else:
                    notice = [[("class:error", " ✗ "), ("", "Gmail request failed"),
                               ("class:dim", " · " + fit(str(exc), 80).rstrip())]]

            console.clear()
            console.print(banner)

        # The screen only holds our banner (cleared at launch): leave just the session result behind.
        console.clear()
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
        if preview_dir is not None:
            shutil.rmtree(preview_dir, ignore_errors=True)

if __name__ == "__main__":
    interactive_download_main()
