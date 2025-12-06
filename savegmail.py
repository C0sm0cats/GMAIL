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
import logging
import pytz
import re
import io
from email.parser import BytesParser
from email.policy import default as policy_default

logging.getLogger('tzlocal').setLevel(logging.ERROR)

def check_playwright_chromium_browser():
    # Path to the Playwright cache directory
    cache_path = os.path.expanduser("~/.cache/ms-playwright")

    # Initialize flags to check if the browsers are installed
    chromium_installed = False
    chromium_headless_installed = False

    # Loop through the cache and look for chromium directories
    try:
        folders = os.listdir(cache_path)
        if not folders:
            print("\033[92m[INFO] Playwright cache does not exist. Install...\033[0m")
            subprocess.run(["playwright", "install", "chromium"], check=True)
            return
        for folder in folders:
            if folder.startswith("chromium-"):
                chromium_installed = True
            elif folder.startswith("chromium_headless_shell-"):
                chromium_headless_installed = True
    except FileNotFoundError:
        print("\033[92m[INFO] Playwright cache does not exist. Installing Chromium (Playwright) and Headless Chromium (Playwright)...\033[0m")
        subprocess.run(["playwright", "install", "chromium"], check=True)
        print("\033[92m[INFO] Chromium (Playwright) and Headless Chromium (Playwright) installed successfully.\033[0m")
        return

    # If either Chromium or Headless Chromium is missing, install the missing one
    if not chromium_installed and not chromium_headless_installed:
        print("\033[92m[INFO] Both Chromium (Playwright) and Headless Chromium (Playwright) are missing. Installing...\033[0m")
        subprocess.run(["playwright", "install", "chromium"], check=True)  # Install Chromium (both versions)
        print("\033[92m[INFO] Chromium (Playwright) and Headless Chromium (Playwright) installed successfully.\033[0m")
    elif not chromium_installed:
        print("\033[92m[INFO] Chromium (Playwright) is missing. Installing Chromium (Playwright)...\033[0m")
        subprocess.run(["playwright", "install", "chromium"], check=True)  # Install Chromium
        print("\033[92m[INFO] Chromium (Playwright) installed successfully.\033[0m")
    elif not chromium_headless_installed:
        print("\033[92m[INFO] Headless Chromium (Playwright) is missing. Installing Headless Chromium (Playwright)...\033[0m")
        subprocess.run(["playwright", "install", "chromium"], check=True)  # Install Chromium (Headless version)
        print("\033[92m[INFO] Headless Chromium (Playwright) installed successfully.\033[0m")
    else:
        print("\033[92m[INFO] Both Chromium (Playwright) and Headless Chromium (Playwright) are already installed.\033[0m")
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                browser.close()
            print("\033[92m[INFO] Chromium is functional.\033[0m")
        except Exception as e:
            print(f"\033[91m[ERROR] Chromium is not functional: {e}\033[0m")
            print("\033[92m[INFO] Reinstalling Chromium (Playwright)...\033[0m")
            subprocess.run(["playwright", "install", "chromium"], check=True)
            print("\033[92m[INFO] Chromium (Playwright) and Headless Chromium (Playwright) reinstalled successfully.\033[0m")

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
    message = service.users().messages().get(userId=user_id, id=msg_id, format='raw').execute()
    raw = message['raw']
    email_bytes = base64.urlsafe_b64decode(raw)
    msg = BytesParser(policy=policy_default).parse(io.BytesIO(email_bytes))

    # Extract headers
    subject = msg['Subject'] or ""
    file_safe_subject = subject.replace("/", "-").replace("\\", "-").replace(":", "-").replace("*", "-").replace("+", "-").replace("é", "e").replace("à", "a")
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
    html_part = msg.get_body(preferencelist=('html'))
    if html_part:
        html_content = html_part.get_content()
    else:
        plain_part = msg.get_body(preferencelist=('plain'))
        if plain_part:
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
        # List messages in trash
        results = service.users().messages().list(userId='me', labelIds=['TRASH']).execute()
        messages = results.get('messages', [])
        
        if not messages:
            print("The trash is already empty.")
            return

        # Permanently delete messages
        for msg in messages:
            service.users().messages().delete(userId='me', id=msg['id']).execute()

        print(f"{len(messages)} message(s) permanently deleted from trash.")

    except Exception as e:
        print(f"Error while emptying trash: {e}")


def main():
    import sys
    
    # Check if the --trash option is passed
    if '--trash' in sys.argv:
        creds = authenticate()
        service = build("gmail", "v1", credentials=creds)
        empty_trash(service)
        return
        
    os.system('clear')
    creds = authenticate()
    try:
        check_playwright_chromium_browser()
        service = build("gmail", "v1", credentials=creds)
        user_id = "me"
        label_name = "HasAttachment"
        label_name_processed = "HasAttachment/SavedAsPDF"

        if not os.path.exists(DOWNLOAD_PATH):
            os.makedirs(DOWNLOAD_PATH)

        label_id = None
        label_name_processed_id = None

        labels = service.users().labels().list(userId=user_id).execute().get("labels", [])
        for label in labels:
            if label["name"] == label_name_processed:
                label_name_processed_id = label["id"]
                break

        for label in labels:
            if label["name"] == label_name:
                label_id = label["id"]
                break

        if label_id:
            response = service.users().messages().list(userId=user_id, labelIds=[label_id]).execute()
            messages = response.get("messages", [])
            if messages:
                print(f"[INFO] {len(messages)} email(s) found → sorting by date (oldest first) ...")
                dated_messages = []
                for msg in messages:
                    try:
                        msg_detail = service.users().messages().get(
                            userId=user_id,
                            id=msg['id'],
                            fields='internalDate'
                        ).execute()
                        internal_date = int(msg_detail.get('internalDate', 0))
                        dated_messages.append((internal_date, msg['id']))
                    except Exception as e:
                        print(f"[WARNING] Could not get date for message {msg['id']}: {e}")
                        dated_messages.append((0, msg['id']))
                dated_messages.sort(key=lambda x: x[0])
                messages = [{"id": msg_id} for _, msg_id in dated_messages]
                print("[INFO] Sorting done. Processing from oldest to newest.\n")
                for message in messages:
                    msg_id = message["id"]
                    print(f"\033[92m[INFO] Starting to save email and attachment(s) for message ID {msg_id}\033[0m")
                    service.users().messages().modify(userId=user_id, id=msg_id, body={"removeLabelIds": [label_id]}).execute()
                    service.users().messages().modify(userId=user_id, id=msg_id, body={"addLabelIds": [label_name_processed_id]}).execute()
                    #service.users().messages().delete(userId=user_id, id=msg_id).execute()
                    save_email_and_attachments(service, user_id, msg_id, DOWNLOAD_PATH)
                print(f"[INFO] {len(messages)} email(s) processed. Goodbye!")

            else:
                print("[INFO] No emails to process with label '{}' for PDF generation.".format(label_name))
        else:
            print(f"Label '{label_name}' not found.")

    except HttpError as error:
        print(f"An error occurred: {error}")


if __name__ == "__main__":
    main()
