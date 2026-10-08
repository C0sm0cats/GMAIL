import os
import pathlib
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
import shutil
import tempfile
import webbrowser
from urllib.parse import quote
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
ACCOUNT = None  # signed-in address, so emails sent to yourself show "Sent · me"
USER_LABELS = {}  # your own Gmail label ids -> names, shown and filterable like categories


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


def discard_pending_keys(app_input=None):
    """Drop keys typed while an action ran, so they never trigger actions blindly.

    Key auto-repeat while a PDF viewer grabbed the focus once queued p presses that kept relaunching
    previews, one per run of the list.
    """
    if sys.stdin.isatty():
        try:
            import termios
            termios.tcflush(sys.stdin.fileno(), termios.TCIFLUSH)
        except (ImportError, OSError):
            pass  # Windows: no termios, nothing more to drop than the typeahead below
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
            attachments_files.append(filename)
            if save_attachments:
                payload = part.get_payload(decode=True)
                path = os.path.join(save_dir, filename)
                written.append(path)
                with open(path, 'wb') as f:
                    f.write(payload)
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
            attachment_url = pathlib.Path(os.path.abspath(attachment_path)).as_uri()  # file:///C:/… on Windows
            # Previews don't write attachments, so there is no file to link to.
            label = f"<a href='{attachment_url}'>{attachment}</a>" if save_attachments else attachment
            attachments_html_footer += f"  <li style='margin-bottom: 0;'><h6 style='margin: 0; padding: 0;'>{label}</h6></li>\n"
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


def user_labels(service, user_id):
    """Your own Gmail labels, {id: name} (system labels and categories left out)."""
    try:
        labels = service.users().labels().list(userId=user_id).execute().get("labels", [])
    except HttpError as exc:
        debug(f"Could not list labels: {exc}")
        return {}
    return {label["id"]: label["name"] for label in labels if label.get("type") == "user"}


def refresh_labels(service, user_id, messages):
    """Re-read the labels (read / unread, star, Inbox…) of loaded emails, changed in Gmail meanwhile.

    Updates messages in place; returns how many changed.
    """
    details, _ = run_batched(service, [message["id"] for message in messages], lambda msg_id:
                             service.users().messages().get(userId=user_id, id=msg_id, format="minimal",
                                                            fields="id,labelIds"))
    changed = 0
    for message in messages:
        labels = details.get(message["id"], {}).get("labelIds")
        if labels is not None and set(labels) != set(message.get("labels", [])):
            message["labels"] = labels
            changed += 1
    return changed


def mark_read(service, user_id, messages):
    """Mark emails as read in Gmail and locally (preview and open count as reading them)."""
    unread = [message for message in messages if "UNREAD" in message.get("labels", [])]
    if not unread:
        return
    try:
        modify_labels(service, user_id, [message["id"] for message in unread], remove=["UNREAD"])
    except HttpError as exc:
        debug(f"Could not mark as read: {exc}")
        return
    for message in unread:
        message["labels"] = [label for label in message["labels"] if label != "UNREAD"]


def modify_labels(service, user_id, ids, add=(), remove=()):
    """Add / remove Gmail labels (STARRED, INBOX, SPAM…) on messages, in one call per 1000."""
    for start in range(0, len(ids), 1000):
        body = {"ids": ids[start:start + 1000], "addLabelIds": list(add), "removeLabelIds": list(remove)}
        service.users().messages().batchModify(userId=user_id, body=body).execute()


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


METADATA_FIELDS = "id,threadId,internalDate,labelIds,sizeEstimate,payload(mimeType,headers),snippet"
# Tab cycles through these views; each is the Gmail search added to --query.
# Archived is ours, not a Gmail label: archiving only removes INBOX, so it is All mail minus the rest.
VIEWS = [("All mail", ""), ("Inbox", "in:inbox"), ("Archived", "-in:inbox -in:sent -in:drafts -in:chats"),
         ("Starred", "is:starred"), ("Sent", "in:sent"),
         ("Drafts", "in:drafts"), ("Spam", "in:spam"), ("Trash", "in:trash")]
# Each view's color, for its tab and the header info, so you see at a glance where you are.
# Sent and Drafts match their sender colors in the list.
VIEW_COLORS = {"All mail": "ansicyan", "Inbox": "ansiblue", "Archived": "ansigreen", "Starred": "ansiyellow",
               "Sent": "ansimagenta", "Drafts": "ansired", "Spam": "#ff8700", "Trash": "ansibrightblack"}
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
    if kind == "draft":
        sender = "Draft"
    elif kind == "sent":
        recipient = (message.get("to") or "").split(",")[0]
        is_me = ACCOUNT and parseaddr(recipient)[1].lower() == ACCOUNT.lower()
        sender = "Sent · " + ("me" if is_me else sender_name(recipient))
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
        "party": parseaddr(((message.get("to") or "").split(",")[0]) if kind == "sent"
                           else message.get("from") or "")[1].lower(),
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
    ("r", "refresh from Gmail: new emails, deleted or moved ones, read / unread, stars and labels"),
    ("p", "preview as PDF, exactly as it would be saved (nothing written to the download folder); marks as read"),
    ("o", "open the current email in Gmail, in your browser; marks as read"),
    ("*", "star / unstar in Gmail"),
    ("!", "mark as unread / read in Gmail (e.g. to keep an email to do after p or o)"),
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
            "cursor_id": None, "sort": "date"}


def pick_messages(messages, load_more=None, state=None, notice=(), undo_label=None, total=None,
                  views=("All mail",), view=0, badges=None):
    """Interactive multi-select list over messages (extended in place when older emails load).

    Returns (action, chosen messages) where action is "download" (save + trash), "save",
    "trash", "delete" (permanent), "empty_trash", "restore", "not_spam", "archive", "unarchive", "preview", "star", "unread",
    "open", "undo",
    "refresh", "next_view", "prev_view" or "quit".
    badges maps view names to (count text, "unread" | "total") shown in their tab.
    views are the tab names shown in the header, view the current one; the Trash view swaps
    enter / d (meaningless there) for R restore.
    load_more() returns (older messages sorted newest first, whether even older ones remain).
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
    state.update(filtering=False, loading=False, confirm=None, help=False, exhausted=load_more is None)
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
        if unread:
            count += f", {unread} unread"
        parts = []
        for position, name in enumerate(views):
            text, kind = (badges or {}).get(name, (None, None))
            label = f" {name} ({text}) " if text else f" {name} "
            style = "class:tab.current" if position == view else "class:tab.badge" if kind == "unread" else "class:tab"
            parts.append((style, label))
        parts.append(("class:view", f" · {count} · " + ("largest first" if state["sort"] == "size" else "newest first")))
        if state["query"]:
            parts.append(("class:dim", f" · {len(indexes)} match "))
            parts.append(("class:accent", state["query"]))
        selected = len(state["selected"])
        if selected:
            status = f"{selected} selected "
            if hidden(state["selected"]):
                status = f"{selected} selected · {hidden(state['selected'])} hidden by the filter "
            gap = max(2, size().columns - sum(cell_len(text) for _, text in parts) - cell_len(status) - 1)
            parts += [("", " " * gap), ("class:checked", status)]
        return parts

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
        elif state["filtering"]:
            hint = [("class:accent", " / "), ("", state["query"]), ("class:accent", "▏"),
                    ("class:dim", "   enter apply · esc clear")]
        else:
            # ↑↓ left out: obvious, and the line is full.
            browse = [("space", "select"), ("a", "all"), ("A", "sender"), ("/", "filter"),
                      ("z", "by date" if state["sort"] == "size" else "by size")]
            if not state["exhausted"]:
                browse.append(("m", "loading…" if state["loading"] else "more"))
            browse += [("r", "refresh"), ("Tab", "views"), ("?", "help"), ("q", "quit")]
            delete = ([] if in_trash else [("d", "trash")]) + [("D", "delete permanently"), ("T", "empty trash")]
            if undo_label:
                delete.append(("u", f"undo {undo_label}"))
            email = [("p", "preview"), ("o", "open in Gmail"), ("*", "star"), ("!", "unread")]
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
    browsing = ~filtering & ~confirming & ~helping
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
        party = rows[indexes[state["cursor"]]]["party"]
        ids = {messages[index]["id"] for index in indexes if party and rows[index]["party"] == party}
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

    @bindings.add("r", filter=browsing)
    def _(event):
        event.app.exit(result=("refresh", []))

    @bindings.add("u", filter=browsing & Condition(lambda: bool(undo_label)))
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
            # Older emails go at the bottom, so the cursor stays where it is.
            messages.extend(older)
            rows.extend(message_row(message) for message in older)
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
        "columns": "fg:ansibrightblack underline",
        "tab": "fg:ansibrightblack",
        # Current view: its tab filled with the view color, the header info written in it.
        "tab.current": f"reverse bold fg:{VIEW_COLORS.get(views[view], 'ansicyan')}",
        "view": f"fg:{VIEW_COLORS.get(views[view], 'ansicyan')}",
        "tab.badge": "fg:default bold",
        "dim": "fg:ansibrightblack",
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
        "row.current": "bg:#303030",
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
    result = app.run(in_thread=True) or ("quit", [])
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
                                views=("All mail",), view=0, badges=None):
    """Pick emails interactively, or by typed numbers when not attached to a terminal.

    Returns (action, messages); see pick_messages for the actions.
    """
    if sys.stdin.isatty() and sys.stdout.isatty():
        return pick_messages(messages, load_more, state, notice, undo_label, total, views, view, badges)
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

    def get_browser():
        """Start Chromium on first use and keep it for the rest of the session."""
        nonlocal playwright, browser
        if browser is None:
            playwright = sync_playwright().start()
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
        banner = (
            f" [bold]savegmail[/]  [dim]·[/]  {escape(account)}  [dim]·  query:[/] "
            f"{escape(args.query) if args.query else '[dim](all)[/]'}  [dim]·  →[/] {escape(shown_dir)}\n"
        )
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
            def load_more():
                before = f"before:{view['floor'] // 1000 + 1}"  # Gmail dates are in seconds; duplicates dropped
                older, token = list_candidate_messages(
                    service, user_id, query=f"{view['query']} {before}".strip(), max_results=args.max,
                    in_trash=view["in_trash"],
                )
                known = {message["id"] for message in view["messages"]}
                older = [message for message in older if message["id"] not in known]
                if older:
                    view["floor"] = min(view["floor"], min(message["internalDate"] for message in older))
                view["more"] = token is not None
                return older, view["more"]
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
            except HttpError as exc:
                return [[("class:error", " ✗ "), ("", "Refresh failed"), ("class:dim", " · " + fit(str(exc), 80).rstrip())]]
            drop(view, removed)
            try:
                # Read / unread, stars… changed in Gmail meanwhile (web, phone, o).
                updated = refresh_labels(service, user_id, view["messages"])
            except HttpError as exc:
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

        def moved_emails():
            """Emails changed place (trash, restore, delete): other views refresh when next shown."""
            nonlocal badges_stale
            badges_stale = True
            for view in views:
                if view is not views[current] and view["loaded"]:
                    view["stale"] = True

        def update_badges():
            nonlocal badges
            badges = view_badges(service, user_id, {view["name"]: view["query"] for view in views}, bool(args.query))

        badges, badges_stale = {}, True
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
        totals = {"saved": 0, "trashed": 0, "deleted": 0}
        # Back to the list after every action, until the user quits.
        while True:
            if badges_stale:
                # Tab counters change when emails move, get starred or arrive (r).
                update_badges()
                badges_stale = False
            view = views[current]
            messages, state = view["messages"], view["state"]
            action, chosen = ask_user_to_select_messages(
                messages, load_more_for(view) if view["more"] else None, state, notice, undo_text(undo),
                view["total"], [view["name"] for view in views], current, badges,
            )
            if action == "quit" or (
                action not in {"undo", "empty_trash", "refresh", "next_view", "prev_view"} and not chosen
            ):
                break
            ids = {message["id"] for message in chosen}

            if action in {"next_view", "prev_view"}:
                current = (current + (1 if action == "next_view" else -1)) % len(views)
                view = views[current]
                notice = []
                if not view["loaded"]:
                    load_view(view)
                elif view["stale"]:
                    notice = refresh_view(view, quiet=True)

            elif action == "preview":
                # Previews live in a session temp dir (never in the download folder), removed on quit.
                preview_dir = preview_dir or tempfile.mkdtemp(prefix="savegmail-preview-")
                failed = preview_messages(service, user_id, chosen, get_browser(), preview_dir)
                mark_read(service, user_id, [message for message in chosen if message["id"] not in failed])
                badges_stale = True
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
                    try:
                        modify_labels(service, user_id, [message["id"] for message in undo["archived"]], add=["INBOX"])
                    except HttpError as exc:
                        errors.update({message["id"]: exc for message in undo["archived"]})
                    else:
                        unarchived = undo["archived"]
                if restored or unarchived:
                    # Emails go back to whichever views they belong to.
                    moved_emails()
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
                stuck = [message for message in undo["trashed"] if message["id"] in errors]
                stuck_archived = [message for message in undo.get("archived", []) if message["id"] in errors]
                undo = {"label": undo["label"], "trashed": stuck, "archived": stuck_archived,
                        "files": {msg_id: undo["files"][msg_id] for msg_id in errors if msg_id in undo["files"]}
                        } if stuck or stuck_archived else None

            elif action in {"archive", "not_spam", "unarchive"}:
                # Archive leaves the Inbox; "not spam" and unarchive go back to it, like in Gmail.
                add, remove = {"archive": ([], ["INBOX"]), "not_spam": (["INBOX"], ["SPAM"]),
                               "unarchive": (["INBOX"], [])}[action]
                try:
                    modify_labels(service, user_id, list(ids), add=add, remove=remove)
                except HttpError as exc:
                    notice = [[("class:error", " ✗ "), ("", f"Could not {'archive' if action == 'archive' else 'move'} "
                                                         f"{plural(len(ids), 'email')}"),
                               ("class:dim", " · " + fit(str(exc), 80).rstrip())]]
                else:
                    for message in chosen:
                        message["labels"] = [label for label in message.get("labels", []) if label not in remove] + add
                    if view["name"] in {"Inbox", "Spam", "Archived"}:
                        drop(view, ids)
                    moved_emails()
                    if action == "archive":
                        undo = {"label": "archive", "trashed": [], "files": {}, "archived": chosen}
                        notice = [[("class:checked", " ✓ "), ("", f"{plural(len(chosen), 'email')} archived"),
                                   ("class:dim class:keyhint", " · u undo")]]
                    else:
                        notice = [[("class:checked", " ✓ "), ("", f"{plural(len(chosen), 'email')} moved to the Inbox")]]

            elif action == "restore":
                with console.status("[dim]Restoring from trash…[/]"):
                    errors = untrash_messages(service, user_id, list(ids))
                restored = [message for message in chosen if message["id"] not in errors]
                drop(view, {message["id"] for message in restored})
                if restored:
                    moved_emails()
                notice = [[("class:checked", " ↶ "), ("", f"{plural(len(restored), 'email')} restored from trash")]]
                notice += failure_notice(chosen, {msg_id: str(exc) for msg_id, exc in errors.items()})

            elif action == "trash":
                with console.status("[dim]Moving to trash…[/]"):
                    errors = trash_messages(service, user_id, list(ids))
                trashed = [message for message in chosen if message["id"] not in errors]
                drop(view, {message["id"] for message in trashed})
                if trashed:
                    undo = {"label": "trash", "trashed": trashed, "files": {}}
                    moved_emails()
                totals["trashed"] += len(trashed)
                notice = [[("class:checked", " ✓ "), ("", f"{plural(len(trashed), 'email')} moved to trash (not saved)"),
                           ("class:dim class:keyhint", " · u undo" if trashed else "")]]
                notice += failure_notice(chosen, {msg_id: str(exc) for msg_id, exc in errors.items()})

            elif action == "open":
                open_quietly(gmail_url(account, chosen[0]["id"]))
                # Gmail marks it read once shown; do it now so the list and counters agree right away.
                mark_read(service, user_id, chosen)
                badges_stale = True

            elif action == "unread":
                # Like star: mark them all unread, unless they all already are, then mark them read.
                unread = not all("UNREAD" in message.get("labels", []) for message in chosen)
                try:
                    modify_labels(service, user_id, list(ids), **{"add" if unread else "remove": ["UNREAD"]})
                except HttpError as exc:
                    notice = [[("class:error", " ✗ "), ("", "Could not change the read state"),
                               ("class:dim", " · " + fit(str(exc), 80).rstrip())]]
                else:
                    for message in chosen:
                        labels = [label for label in message.get("labels", []) if label != "UNREAD"]
                        message["labels"] = labels + ["UNREAD"] if unread else labels
                    badges_stale = True
                    notice = [[("class:checked", " ● " if unread else " ○ "),
                               ("", f"{plural(len(chosen), 'email')} marked as {'unread' if unread else 'read'}")]]

            elif action == "star":
                badges_stale = True
                # Like Gmail: star them all, unless they all are already starred.
                star = not all("STARRED" in message.get("labels", []) for message in chosen)
                try:
                    modify_labels(service, user_id, list(ids), **{"add" if star else "remove": ["STARRED"]})
                except HttpError as exc:
                    notice = [[("class:error", " ✗ "), ("", "Could not change the star"),
                               ("class:dim", " · " + fit(str(exc), 80).rstrip())]]
                else:
                    for message in chosen:
                        labels = [label for label in message.get("labels", []) if label != "STARRED"]
                        message["labels"] = labels + ["STARRED"] if star else labels
                    notice = [[("class:star", " ★ " if star else " ☆ "),
                               ("", f"{plural(len(chosen), 'email')} {'starred' if star else 'unstarred'}")]]

            elif action == "refresh":
                notice = refresh_view(view)
                badges_stale = True

            elif action == "empty_trash":
                try:
                    with console.status("[dim]Emptying trash…[/]"):
                        trash_ids = list_trash_ids(service, user_id)
                        delete_messages(service, user_id, trash_ids)
                except Exception as exc:
                    notice = [[("class:error", " ✗ "), ("", "Could not empty the trash"),
                               ("class:dim", " · " + fit(str(exc), 80).rstrip())]]
                else:
                    moved_emails()
                    if view["in_trash"]:
                        drop(view, {message["id"] for message in messages})
                    # Trashed emails are gone for good: they can't be restored, and their saved files are
                    # now the only copy, so keep them. Only an undo of s (emails still in Gmail) remains.
                    if undo:
                        trashed_ids = {message["id"] for message in undo["trashed"]}
                        kept = {msg_id: files for msg_id, files in undo["files"].items() if msg_id not in trashed_ids}
                        undo = {"label": undo["label"], "trashed": [], "files": kept} if kept else None
                    totals["deleted"] += len(trash_ids)
                    notice = [[("class:checked", " ✓ "),
                               ("", f"Trash emptied · {plural(len(trash_ids), 'email')} permanently deleted")]]

            elif action == "delete":
                try:
                    with console.status("[dim]Deleting…[/]"):
                        delete_messages(service, user_id, list(ids))
                except Exception as exc:
                    # batchDelete is all-or-nothing: nothing was deleted.
                    notice = [[("class:error", " ✗ "), ("", f"Could not delete {plural(len(ids), 'email')}"),
                               ("class:dim", " · " + fit(str(exc), 80).rstrip())]]
                else:
                    drop(view, ids)
                    moved_emails()
                    totals["deleted"] += len(ids)
                    # Saved files of deleted emails are now the only copy: an undo of s must not remove them.
                    if undo:
                        kept = {msg_id: files for msg_id, files in undo["files"].items() if msg_id not in ids}
                        undo = ({"label": undo["label"], "trashed": undo["trashed"], "files": kept}
                                if kept or undo["trashed"] else None)
                    notice = [[("class:checked", " ✓ "), ("", f"{plural(len(ids), 'email')} permanently deleted")]]

            else:
                trash_after = action == "download"
                saved, attachments, failed, files = save_messages(service, user_id, chosen, save_dir, get_browser(), trash_after)
                saved_ids = {message["id"] for message in saved}
                totals["saved"] += len(saved)
                summary = f"{plural(len(saved), 'PDF')} · {plural(attachments, 'attachment')}"
                if trash_after:
                    drop(view, saved_ids)
                    moved_emails()
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
                notice = [[("class:checked", " ✓ "), ("", summary), ("class:dim", f" → {shown_dir}")]]
                if saved:
                    notice[0].append(("class:dim class:keyhint", " · u undo"))
                notice += failure_notice(chosen, failed)

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
