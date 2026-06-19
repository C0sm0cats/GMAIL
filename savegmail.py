import os
import base64
from playwright.sync_api import sync_playwright
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
import shutil
from email.parser import BytesParser
from email.policy import default as policy_default

logging.getLogger('tzlocal').setLevel(logging.ERROR)

def check_playwright_chromium_browser():
    def launch_chromium():
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            browser.close()

    try:
        launch_chromium()
    except Exception as error:
        print(f"\033[93m[WARNING] Playwright Chromium is not ready: {error}\033[0m")
        print("\033[92m[INFO] Installing Chromium for Playwright...\033[0m")
        subprocess.run([sys.executable, "-m", "playwright", "install", "chromium"], check=True)
        launch_chromium()

    print("\033[92m[INFO] Chromium (Playwright) is functional.\033[0m")

SCOPES = ["https://mail.google.com/"]
# SCOPES = ["https://www.googleapis.com/auth/gmail.readonly", "https://www.googleapis.com/auth/gmail.modify"]
DOWNLOAD_PATH = '~/Downloads/'

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


def authenticate():
    creds = None
    token_path = "token.json"
    if os.path.exists(token_path):
        creds = Credentials.from_authorized_user_file(token_path, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                print("[INFO] Token refreshed:")
                print("[INFO] Expiry:", convert_expiry_to_local_time(creds.expiry))
            except Exception as e:
                print(f"Error refreshing token: {e}")
                flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
                creds = flow.run_local_server(port=0)
                print("Expiry:", convert_expiry_to_local_time(creds.expiry))
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)
            print("[INFO] Expiry:", convert_expiry_to_local_time(creds.expiry))
        with open(token_path, "w") as token:
            token.write(creds.to_json())
    return creds

def save_email_and_attachments(service, user_id, msg_id, save_dir):
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
        safe = safe.strip().rstrip(". ")
        return safe or "No_Subject"

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
        print("[INFO] Email body selected: HTML")
        html_content = html_part.get_content()
    else:
        plain_part = msg.get_body(preferencelist=('plain',))
        if plain_part:
            print("[INFO] Email body selected: plain text")
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
            print("[WARNING] No HTML or plain text body found in email.")
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
        counter = 1
        candidate = filename

        while (os.path.exists(os.path.join(save_dir, candidate)) or 
               candidate in used_filenames):
            candidate = f"{base}({counter}){ext}"
            counter += 1

        used_filenames.add(candidate)
        return candidate

    for part in msg.walk():
        print(f"[DEBUG] Part: Content-Type={part.get_content_type()}, Content-ID={part.get('Content-ID')}, Filename={part.get_filename()}, Disposition={part.get_content_disposition()}")
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
            with open(path, 'wb') as f:
                f.write(payload)
            attachments_files.append(filename)
            print(f"\033[36m[INFO] Attachment saved: {filename}\033[0m")

        # Handle images (inline or otherwise): Always embed if image and has CID
        if content_type.startswith('image/'):
            payload = part.get_payload(decode=True)
            base64_data = base64.b64encode(payload).decode('utf-8')
            data_url = f"data:{content_type};base64,{base64_data}"
            if content_id:
                content_id = content_id.strip('<>')
                cid_map[content_id] = data_url
                print(f"[DEBUG] Mapped CID {content_id} to data URL: {data_url[:50]}...")
            elif not filename:  # Generate CID only for true inline without filename
                generated_cid = f"generated_cid_{counter}"
                cid_map[generated_cid] = data_url
                print(f"[DEBUG] Generated CID {generated_cid} for inline image without Content-ID: {data_url[:50]}...")
                counter += 1

    # Replace cid: in HTML with data: URLs
    def replace_cid(match):
        cid_value = match.group(1)
        if cid_value in cid_map:
            print(f"[DEBUG] Replacing CID: {cid_value} with data URL: {cid_map[cid_value][:50]}...")
            return f'src="{cid_map[cid_value]}"'
        print(f"[WARNING] No mapping found for CID: {cid_value}")
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

    try:
        with sync_playwright() as p:
            def has_dynamic_content(html_content):
                dynamic_patterns = {
                    "script tags": r"<script.*?>.*?</script>",
                    "iframe tags": r"<iframe.*?>.*?</iframe>",
                    "JS frameworks": r"data-reactroot|ng-app|vue",
                    "AJAX calls": r"XMLHttpRequest|fetch",
                    "Media queries": r"@media",
                    "CSS transitions/animations": r"transition|animation",
                    "JavaScript timers": r"setInterval|setTimeout",
                    "AJAX content markers": r"data-ajax",
                    "Vue.js or React markers": r"v-bind|v-for|data-v-",
                    "WebSocket indicators": r"WebSocket",
                    "Dynamic event listeners": r"addEventListener",
                    "Inline CSS for dynamic styles": r"style=['\"].*?display\s*:\s*none.*?['\"]",
                    "Loading indicators": r'loading|lazy|spinner|progress',
                    "Dynamic data attributes": r"data-\w+",
                    "Content injected by JavaScript": r"document\.write|innerHTML|outerHTML",
                    "MutationObserver": r"MutationObserver",
                    "IntersectionObserver": r"IntersectionObserver",
                    "Lazy-loaded content": r"data-src|data-lazy",
                    "Viewport-related dynamic elements": r"viewport|resize",
                    "SVG graphics": r"<svg",
                    "Web components": r"<\w+-\w+",
                    "Dynamic background images": r"background-image\s*:\s*url",
                }
                for desc, pattern in dynamic_patterns.items():
                    if re.search(pattern, html_content, re.IGNORECASE):
                        print(f"Dynamic content detected: Found {desc}")
                        return True
                return False

            headless_mode = not has_dynamic_content(html_content)
            print(f"headless_mode: {headless_mode}")

            browser = p.chromium.launch(headless=headless_mode)
            page = browser.new_page()
            page.set_content(html_content, timeout=120000)
            page.wait_for_load_state('networkidle')

            header_template = """
                <div style="font-size: 10px; color: #666; text-align: center; width: 100%">
                    <h3 style='margin-top: 0px;'>{subject}</h3>
                    <div>From : {fro}</div>
                    <div>Reply To : {reply}</div>
                    <div>To : {to}</div>
                    <div>Cc : {cc}</div>
                    <div>Date : {date}</div>
                </div>
            """.format(fro=fro, reply=reply, to=to, cc=cc, date=date, subject=subject)
            footer_template = f"""
                <div style="font-size: 10px; color: #666; text-align: center; width: 100%">
                    {attachments_html_footer}
                    <div style="margin-top: 8px;"><a href='https://mail.google.com/mail/u/0/#inbox/{msg_id}'>View in Gmail</a></div>
                    <span class="pageNumber"></span> / <span class="totalPages"></span>
                </div>
            """

            page.pdf(
                format='A4',
                print_background=True,
                display_header_footer=True,
                header_template=header_template,
                footer_template=footer_template,
                margin={"top": "150px", "bottom": "150px", "left": "0", "right": "0"},
                path=final_pdf_path
            )

            browser.close()
    except Exception as e:
        print(f"[ERROR] Unexpected error during PDF generation for message {msg_id}: {e}")
        raise

    print(f"\033[36m[INFO] PDF document saved for message ID {msg_id} at {save_dir}\033[0m")
    now = datetime.now()
    timestamp = now.strftime("%y%m%d_%H%M%S")
    milliseconds = now.microsecond // 1000
    new_pdf_path = os.path.join(save_dir, f"{timestamp}{milliseconds}_{file_safe_subject}.pdf")
    os.rename(final_pdf_path, new_pdf_path)
    print(f"\033[34m  - {os.path.basename(new_pdf_path)}\033[0m")
    print(f"\033[92m[INFO] Finished saving email and attachment(s) for message ID {msg_id}\033[0m\n")

def empty_trash(service):
    """
    Permanently deletes all messages from the trash.
    """
    try:
        messages = []
        request = service.users().messages().list(userId='me', labelIds=['TRASH'])
        while request is not None:
            results = request.execute()
            messages.extend(results.get('messages', []))
            request = service.users().messages().list_next(request, results)

        if not messages:
            print("The trash is already empty.")
            return

        # Permanently delete messages
        for msg in messages:
            service.users().messages().delete(userId='me', id=msg['id']).execute()

        print(f"{len(messages)} message(s) permanently deleted from trash.")

    except Exception as e:
        print(f"Error while emptying trash: {e}")


def move_message_to_trash(service, user_id, msg_id):
    """Move a Gmail message to trash after a successful local save."""
    service.users().messages().trash(userId=user_id, id=msg_id).execute()
    print(f"\033[93m[INFO] Message moved to Gmail trash: {msg_id}\033[0m")



def extract_header(headers, name, default=""):
    for header in headers or []:
        if header.get("name", "").lower() == name.lower():
            return header.get("value", default)
    return default


def list_candidate_messages(service, user_id, query="", max_results=50):
    """Return Gmail messages matching a search query, sorted oldest first.

    Empty query means: list all visible Gmail messages, letting the user choose
    which ones to download afterwards.
    """
    messages = []
    request = service.users().messages().list(
        userId=user_id,
        q=query,
        maxResults=min(max_results, 500),
    )

    while request is not None and len(messages) < max_results:
        response = request.execute()
        messages.extend(response.get("messages", []))
        if len(messages) >= max_results:
            break
        request = service.users().messages().list_next(request, response)

    detailed_messages = []
    for message in messages[:max_results]:
        msg_id = message["id"]
        try:
            detail = service.users().messages().get(
                userId=user_id,
                id=msg_id,
                format="metadata",
                metadataHeaders=["Subject", "From", "Date"],
                fields="id,threadId,internalDate,payload/headers,snippet",
            ).execute()
            headers = detail.get("payload", {}).get("headers", [])
            detailed_messages.append({
                "id": detail["id"],
                "threadId": detail.get("threadId", ""),
                "internalDate": int(detail.get("internalDate", 0)),
                "date": get_real_date(extract_header(headers, "Date", "No Date")),
                "from": extract_header(headers, "From", ""),
                "subject": extract_header(headers, "Subject", "No Subject"),
                "snippet": detail.get("snippet", ""),
            })
        except Exception as exc:
            print(f"[WARNING] Could not read metadata for message {msg_id}: {exc}")
            detailed_messages.append({
                "id": msg_id,
                "threadId": "",
                "internalDate": 0,
                "date": "Invalid Date",
                "from": "",
                "subject": "No Subject",
                "snippet": "",
            })

    detailed_messages.sort(key=lambda item: item["internalDate"])
    return detailed_messages


def shorten(value, width):
    value = re.sub(r"\s+", " ", value or "").strip()
    if width <= 0:
        return ""
    if len(value) <= width:
        return value
    return value[: max(0, width - 1)] + "…"


def supports_color():
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def colorize(text, code):
    if not supports_color():
        return text
    return f"\033[{code}m{text}\033[0m"


def strip_ansi(text):
    return re.sub(r"\033\[[0-9;]*m", "", text)


def visible_len(text):
    return len(strip_ansi(text))


def line_pad(text, width):
    """Pad a full line to the requested visible width."""
    return text + " " * max(0, width - visible_len(text))


def terminal_width(default=118):
    return max(88, min(shutil.get_terminal_size((default, 24)).columns, 160))


def fit_ansi(text, width):
    """Pad plain/colored text to a visible width after stripping ANSI codes."""
    plain = strip_ansi(text)
    fitted = shorten(plain, width)
    return fitted + " " * max(0, width - len(fitted))


def clean_sender(sender):
    sender = re.sub(r"\s+", " ", sender or "").strip()
    sender = sender.replace('"', '')
    match = re.match(r"(.+?)\s*<([^>]+)>", sender)
    if match:
        name, email_addr = match.groups()
        name = name.strip() or email_addr
        return f"{name} <{email_addr}>"
    return sender or "—"


def format_email_date(date_text):
    date_text = date_text or ""
    match = re.match(r"(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2})", date_text)
    if match:
        return f"{match.group(1)} {match.group(2)}"
    return date_text or "—"


def print_box_line(width, left="╭", fill="─", right="╮"):
    print(colorize(left + fill * (width - 2) + right, "90"))


def print_box_text(text, width, accent=False):
    content_width = width - 4
    clean = shorten(text, content_width)
    code = "96;1" if accent else "37"
    print(colorize("│ ", "90") + colorize(line_pad(clean, content_width), code) + colorize(" │", "90"))


def print_candidate_messages(messages):
    width = terminal_width()
    date_w = 16
    num_w = max(3, len(str(len(messages))))
    max_table_width = width

    sender_values = [clean_sender(message.get('from')) for message in messages]
    subject_values = [message.get('subject') or "No Subject" for message in messages]

    from_w = max(
        len("EXPÉDITEUR"),
        min(max((visible_len(sender) for sender in sender_values), default=0), 42),
        22,
    )
    subject_w = max(
        len("SUJET"),
        min(max((visible_len(subject) for subject in subject_values), default=0), 72),
        24,
    )

    # If content is wider than the terminal, shrink subject first, then sender.
    while num_w + date_w + from_w + subject_w + 11 > max_table_width and subject_w > 24:
        subject_w -= 1
    while num_w + date_w + from_w + subject_w + 11 > max_table_width and from_w > 22:
        from_w -= 1

    # Visible width of a row:
    # borders(2) + num/date/from/subject widths + separators/marker(9)
    table_width = num_w + date_w + from_w + subject_w + 11

    print()
    print_box_line(table_width)
    print_box_text("GMAIL · Emails disponibles pour téléchargement", table_width, accent=True)
    print_box_text(f"{len(messages)} email(s) listé(s) · sélection par numéro, plage ou all", table_width)
    print_box_line(table_width, left="├", right="┤")

    header = (
        f" {'N°':>{num_w}}  "
        f" "
        f"{'DATE':<{date_w}}  "
        f"{'EXPÉDITEUR':<{from_w}}  "
        f"{'SUJET':<{subject_w}} "
    )
    print(colorize("│", "90") + colorize(header, "90;1") + colorize("│", "90"))
    print_box_line(table_width, left="├", right="┤")

    for index, message in enumerate(messages, start=1):
        marker = colorize("●", "36") if index % 2 else colorize("•", "90")
        number = colorize(f"{index:>{num_w}}", "96;1")
        date = fit_ansi(format_email_date(message.get('date')), date_w)
        sender = fit_ansi(clean_sender(message.get('from')), from_w)
        subject = fit_ansi(message.get('subject') or "No Subject", subject_w)
        print(
            colorize("│", "90")
            + f" {number} {marker} "
            + colorize(date, "37")
            + "  "
            + colorize(sender, "36")
            + "  "
            + colorize(subject, "97;1")
            + " "
            + colorize("│", "90")
        )
    print_box_line(table_width, left="╰", right="╯")


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
                raise ValueError(f"Sélection invalide: {part}")
            if start > end:
                start, end = end, start
            for number in range(start, end + 1):
                if 1 <= number <= total:
                    selected.add(number - 1)
                else:
                    raise ValueError(f"Numéro hors limite: {number}")
        else:
            try:
                number = int(part)
            except ValueError:
                raise ValueError(f"Sélection invalide: {part}")
            if 1 <= number <= total:
                selected.add(number - 1)
            else:
                raise ValueError(f"Numéro hors limite: {number}")
    return sorted(selected)


def ask_user_to_select_messages(messages):
    if not messages:
        return []

    print_candidate_messages(messages)
    print(colorize("\nSélection", "96;1"))
    print("  " + colorize("1,3,5", "97;1") + "      numéros séparés par virgules/espaces")
    print("  " + colorize("2-6", "97;1") + "        plage de numéros")
    print("  " + colorize("2-6,8-10", "97;1") + "   plages multiples")
    print("  " + colorize("1,3,7-9", "97;1") + "    mélange numéros + plages")
    print("  " + colorize("all", "97;1") + "        tout sélectionner")
    print("  " + colorize("q", "97;1") + "          quitter sans téléchargement")

    while True:
        answer = input("\nVotre sélection > ")
        try:
            selected_indexes = parse_selection(answer, len(messages))
        except ValueError as exc:
            print(colorize(f"[WARNING] {exc}. Réessayez.", "93"))
            continue

        if not selected_indexes:
            return []

        print(colorize("\nSélection retenue :", "96;1"))
        for index in selected_indexes:
            message = messages[index]
            print(f"  {colorize(str(index + 1), '96;1')}. {format_email_date(message['date'])} — {message['subject']}")

        confirm = input("Confirmer le téléchargement ? [o/N] ").strip().lower()
        if confirm in {"o", "oui", "y", "yes"}:
            return [messages[index] for index in selected_indexes]
        print("Sélection annulée. Vous pouvez choisir à nouveau.")


def interactive_download_main():
    import argparse

    parser = argparse.ArgumentParser(
        description=(
            "Liste tous les emails Gmail disponibles, permet de choisir ceux à télécharger en PDF, "
            "puis déplace les emails traités dans la corbeille Gmail."
        )
    )
    parser.add_argument(
        "--query",
        default="",
        help="Recherche Gmail optionnelle pour filtrer la liste (défaut: aucune, donc tous les emails). Ex: 'newer_than:30d', 'from:foo' ou 'has:attachment'.",
    )
    parser.add_argument(
        "--max",
        type=int,
        default=50,
        help="Nombre maximum d'emails à afficher (défaut: 50).",
    )
    parser.add_argument(
        "--download-path",
        metavar="PATH",
        default=DOWNLOAD_PATH,
        help="Dossier de téléchargement (défaut: %(default)s).",
    )
    parser.add_argument(
        "--trash",
        action="store_true",
        help="Vide la corbeille Gmail uniquement. Option manuelle, non lancée automatiquement après téléchargement.",
    )
    args = parser.parse_args()

    if args.trash:
        creds = authenticate()
        service = build("gmail", "v1", credentials=creds)
        empty_trash(service)
        return

    os.system('clear')
    creds = authenticate()
    try:
        service = build("gmail", "v1", credentials=creds)
        user_id = "me"
        save_dir = os.path.expanduser(args.download_path)
        os.makedirs(save_dir, exist_ok=True)

        print(f"[INFO] Recherche Gmail: {args.query or '(aucun filtre — tous les emails)'}")
        print(f"[INFO] Dossier de téléchargement: {save_dir}")
        messages = list_candidate_messages(service, user_id, query=args.query, max_results=args.max)

        if not messages:
            print("[INFO] Aucun email trouvé pour cette recherche.")
            return

        selected_messages = ask_user_to_select_messages(messages)
        if not selected_messages:
            print("[INFO] Aucun email sélectionné. Goodbye!")
            return

        print(f"\n[INFO] {len(selected_messages)} email(s) sélectionné(s). Préparation de Chromium/Playwright...\n")
        check_playwright_chromium_browser()
        print(f"\n[INFO] Traitement du plus ancien au plus récent.\n")
        for message in selected_messages:
            msg_id = message["id"]
            print(f"\033[92m[INFO] Starting to save email and attachment(s) for message ID {msg_id}\033[0m")
            save_email_and_attachments(service, user_id, msg_id, save_dir)
            move_message_to_trash(service, user_id, msg_id)

        print(f"[INFO] {len(selected_messages)} email(s) processed and moved to Gmail trash. Goodbye!")

    except HttpError as error:
        print(f"An error occurred: {error}")

if __name__ == "__main__":
    interactive_download_main()
