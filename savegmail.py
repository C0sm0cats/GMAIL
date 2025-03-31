import os
import base64
from playwright.sync_api import sync_playwright
from flask import Flask, send_from_directory, request
from threading import Thread
import time
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
import requests
import pytz
import re

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

SCOPES = ["https://mail.google.com/"]
# SCOPES = ["https://www.googleapis.com/auth/gmail.readonly", "https://www.googleapis.com/auth/gmail.modify"]
DOWNLOAD_PATH = '~/Downloads/'

PORT = 5000
app = Flask(__name__)
log = logging.getLogger('werkzeug')
log.disabled = True

@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory(DOWNLOAD_PATH, filename)

def shutdown_server():
    print("[INFO] Server Flask shutting down...")
    func = request.environ.get('werkzeug.server.shutdown')
    if func:
        func()

@app.route('/shutdown', methods=['POST'])
def shutdown():
    shutdown_server()
    return '', 200

def run_server():
    try:
        app.run(port=PORT, debug=False)
    except Exception as e:
        print(f"[ERROR] Failed to start Flask server: {e}")
        raise

def wait_for_flask(port, timeout=10):
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            response = requests.get(f"http://127.0.0.1:{port}/")
            if response.status_code == 404:  # Flask répond, même avec une 404 pour une route inexistante
                return True
        except requests.exceptions.ConnectionError:
            time.sleep(0.1)
    raise Exception("Flask server did not start within timeout")

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


def decode_base64(data):
    missing_padding = 4 - len(data) % 4
    if missing_padding:
        data += '=' * missing_padding
    return base64.urlsafe_b64decode(data)


def replace_src_with_url(html_content, attachments_files, port):
    src_pattern = re.compile(r'src=["\']cid:([^"\']+)["\']')

    def replace_src(match):
        cid_value = match.group(1).split('@')[0]
        # print(f"Found cid: {cid_value}")
        for attachment in attachments_files:
            if cid_value in attachment:
                attachment_url = f"http://127.0.0.1:{port}/{attachment}"
                # print(f"Generated URL: {attachment_url}")
                return f'src="{attachment_url}"'

        print(f"No matching attachment found for cid: {cid_value}")
        return match.group(0)

    return re.sub(src_pattern, replace_src, html_content)
    # updated_html_content = re.sub(src_pattern, replace_src, html_content)
    # print("\nUpdated HTML content:")
    # print(updated_html_content)
    # return updated_html_content


def delete_matching_attachments(html_content, attachments_files, download_path):
    url_pattern = re.compile(r'http://127.0.0.1:\d+/(.+?\.(jpg|png|gif|jpeg))')
    urls_in_html = re.findall(url_pattern, html_content)

    print(f"\033[36m[INFO] Cleaning up CID attachment(s) file(s):\033[0m")
    for attachment in attachments_files:
        for url in urls_in_html:
            filename = url[0]
            if filename == attachment:
                attachment_path = os.path.join(download_path, attachment)
                if os.path.exists(attachment_path):
                    os.remove(attachment_path)
                    print(f"\033[34m  - {attachment}\033[0m")


def save_attachments(service, user_id, msg_id, save_dir, attachments_files):
    message = service.users().messages().get(userId=user_id, id=msg_id).execute()
    parts = message['payload'].get('parts', [])
    attachments_html = ""
    attachments_html_pdf = ""
    for part in parts:
        if part.get('filename'):
            filename = part['filename']
            if 'data' in part['body']:
                data = part['body']['data']
            else:
                att_id = part['body']['attachmentId']
                att = service.users().messages().attachments().get(userId=user_id, messageId=msg_id, id=att_id).execute()
                data = att['data']
            file_data = base64.urlsafe_b64decode(data.encode('UTF-8'))
            path = os.path.join(save_dir, filename)
            with open(path, 'wb') as f:
                f.write(file_data)

            now = datetime.now()
            timestamp = now.strftime("%y%m%d_%H%M%S")
            milliseconds = now.microsecond // 1000
            new_filename = f"{timestamp}{milliseconds}_{filename}"
            new_path = os.path.join(save_dir, new_filename)
            os.rename(path, new_path)
            attachments_files.append(new_filename)

    if len(attachments_files) == 1:
        print(f"\033[36m[INFO] 1 Attachment saved for message ID {msg_id} at {DOWNLOAD_PATH}\033[0m")
        print(f"\033[34m  - {attachments_files[0]}\033[0m")
    elif len(attachments_files) > 1:
        print(f"\033[36m[INFO] {len(attachments_files)} Attachments saved for message ID {msg_id} at {DOWNLOAD_PATH}\033[0m")
        for file in attachments_files:
            print(f"\033[34m  - {file}\033[0m")
    else:
        print(f"\033[36m[INFO] No attachments to save for message ID {msg_id} at {DOWNLOAD_PATH}.\033[0m")

    if attachments_files:
        filtered_attachments = [attachment for attachment in attachments_files if attachment]
        if filtered_attachments:
            attachments_html = "<div>Attachments :</div>\n<ul style='list-style-type: none; padding: 0; margin: 0;'>\n"
            attachments_html_pdf = "<div>Attachments :</div>\n<ul style='list-style-type: none; padding: 0; margin: 0;'>\n"
            for attachment in filtered_attachments:
                attachment_path = os.path.join(DOWNLOAD_PATH, attachment)
                attachment_url = f"file://{os.path.abspath(attachment_path)}"
                attachments_html += f"  <li style='margin-bottom: 0;'><h6 style='margin: 0; padding: 0;'><a href='{attachment_url}'>{attachment}</a></h6></li>\n"
                if attachment.lower().endswith('.pdf'):
                    attachments_html_pdf += f"  <li style='margin-bottom: 0;'><h6 style='margin: 0; padding: 0;'><a href='{attachment_url}'>{attachment}</a></h6></li>\n"
            attachments_html += "</ul>\n"
            attachments_html_pdf += "</ul>\n"
    else:
        attachments_html = "<div>No Attachments for this mail</div>"
        attachments_html_pdf = "<div>No PDF Attachments for this mail</div>"
    return attachments_html, attachments_html_pdf


def download_attachment(service, user_id, attachment_id, save_dir, filename, msg_id):
    try:
        attachment = service.users().messages().attachments().get(userId=user_id, messageId=msg_id, id=attachment_id).execute()
        file_data = base64.urlsafe_b64decode(attachment['data'].encode('UTF-8'))
        filepath = os.path.join(save_dir, filename)
        with open(filepath, 'wb') as f:
            f.write(file_data)
        # print(f"Attachment saved to {filepath}")
        return filepath
    except Exception as e:
        print(f"Error downloading attachment {filename}: {e}")
        return None


def save_email_and_attachments(service, user_id, msg_id, save_dir):
    message = service.users().messages().get(userId=user_id, id=msg_id, format="full").execute()

    # print(f"Message: {message}")

    # payload = message.get('payload', {})
    # print(f"Payload: {payload}")

    subject = ""
    if 'payload' in message and 'headers' in message['payload']:
        for header in message['payload']['headers']:
            if header['name'] == 'Subject':
                subject = header['value']
                break

    payload = message.get('payload', {})
    headers = {header['name']: header['value'] for header in payload.get('headers', [])}
    date = headers.get('Date', 'No Date')
    real_date = get_real_date(date)
    date = real_date

    fro = ""
    if 'payload' in message and 'headers' in message['payload']:
        for header in message['payload']['headers']:
            if header['name'] == 'From':
                fro = header['value']
                if '<' in fro and '>' in fro:
                    fro_name, fro_email = fro.split('<', 1)
                    fro_email = fro_email.rstrip('>')
                    fro_email = f" {fro_email}"
                    fro = f"{fro_name.strip()} {fro_email.strip()} "
                break

    reply = ""
    if 'payload' in message and 'headers' in message['payload']:
        for header in message['payload']['headers']:
            if header['name'] == 'Reply-To':
                reply = header['value']
                if '<' in reply and '>' in reply:
                    reply_name, reply_email = reply.split('<', 1)
                    reply_email = reply_email.rstrip('>')
                    reply_email = f" {reply_email}"
                    reply = f"{reply_name.strip()} {reply_email.strip()} "
                break

    to = ""
    cc = ""
    if 'payload' in message and 'headers' in message['payload']:
        for header in message['payload']['headers']:
            if header['name'] == 'To':
                to = header['value']
                if '<' in to and '>' in to:
                    to_name, to_email = to.split('<', 1)
                    to_email = to_email.rstrip('>')
                    to_email = f" {to_email}"
                    to = f"{to_name.strip()} {to_email.strip()} "

            if header['name'] == 'Cc':
                cc = header['value']
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

            if to and cc:
                break

    parts = message.get('payload', {}).get('parts', [])
    attachments_files = []
    server_flask_started = False

    def extract_parts(parts):
        valid_mime_types = ['text/html', 'text/plain', 'multipart/alternative', 'multipart/related', 'multipart/mixed']
        mime_type = None
        data = ""
        html_data = None
        plain_data = None

        # Loop through each part of the email
        for part in parts:
            mime_type = part.get('mimeType')

            # Handle text-based MIME types (HTML, plain text, multipart)
            if mime_type in valid_mime_types:
                # Check if the part has a body with data
                if part.get('body') and part['body'].get('data'):
                    if mime_type == 'text/html':
                        html_data = part['body']['data'] # Store HTML data
                    elif mime_type == 'text/plain':
                        plain_data = part['body']['data'] # Store plain text data
                # Recursively process nested parts if present
                elif 'parts' in part:
                    html_data, plain_data = extract_parts(part['parts'])

            # Handle image attachments (with Content-ID for inline images)
            if mime_type and mime_type.startswith('image/'):
                filename = part.get('filename', '')
                if not filename:
                    # Generate a default filename if none is provided
                    headers_dict = {header['name'].lower(): header['value'] for header in part.get('headers', [])}
                    content_id = headers_dict.get('content-id')
                    if content_id:
                        filename = f"inline_image_{content_id.strip('<>')}.{mime_type.split('/')[1]}"
                    else:
                        continue  # Skip if no filename and no content_id

                # Retrieve headers as a dictionary
                headers_dict = {header['name'].lower(): header['value'] for header in part.get('headers', [])}
                content_id = headers_dict.get('content-id')
                content_disposition = headers_dict.get('content-disposition', '').lower()

                # Ensure the image is inline (has CID and is not an attachment)
                if not content_id or ('attachment' in content_disposition):
                    continue

                # Handle inline images encoded directly in the body
                if part.get('body') and part['body'].get('data'):
                    image_data = part['body']['data'] # Get base64-encoded image data
                    file_path = os.path.join(save_dir, filename) # Define file path
                    with open(file_path, 'wb') as f:
                        f.write(base64.b64decode(image_data)) # Decode and save the image
                    attachments_files.append(filename) # Add to attachments list
                    continue # Move to next part after processing inline image

                # Handle attachments with an attachmentId (original logic)
                attachment_id = part.get('body', {}).get('attachmentId')
                if not attachment_id:
                    continue # Skip if no attachmentId
                file_path = download_attachment(service, user_id, attachment_id, save_dir, filename, msg_id)
                if file_path:
                    attachments_files.append(filename) # Add to attachments list if downloaded

        # Return the extracted data based on priority (HTML first, then plain text)
        if html_data:
            return html_data, 'text/html'
        if plain_data:
            return plain_data, 'text/plain'
        return data, mime_type

    attachments_html, attachments_html_pdf = save_attachments(service, user_id, msg_id, save_dir, attachments_files)

    if 'body' in payload and 'data' in payload['body']:
        data = payload['body']['data']
        mime_type = payload.get('mimeType', '')
    else:
        # print(f"Running extract_parts")
        data, mime_type = extract_parts(parts)

    if data:
        # print(f"data found")
        if mime_type == 'text/plain':
            # print(f"text/plain detected")
            html_content = decode_base64(data).decode('utf-8')
            html_content = re.sub(r'(>>?|>)', r'<br>', html_content)
            html_content = re.sub(r'(On \d{2}/\d{2}/\d{4})', r'<br><br><hr>\1', html_content)
            date_regex = r'((Le|The) \d{1,2} (janv\.|févr\.|mars\.|avr\.|mai\.|juin\.|juil\.|août\.|sept\.|oct\.|nov\.|déc\.|Jan\.|Feb\.|Mar\.|Apr\.|May\.|Jun\.|Jul\.|Aug\.|Sep\.|Oct\.|Nov\.|Dec\.) \d{4}( (à|at) \d{1,2}:\d{2})?)'
            html_content = re.sub(date_regex, r'<hr>\1', html_content)
        elif mime_type == 'text/html':
            # print(f"text/html detected")
            html_content = decode_base64(data).decode('utf-8')
            # print(f"html_content: {html_content}")
            if attachments_files and re.search(r'src=["\']cid:([^"\']+)["\']', html_content):
                print(f"\033[36m[INFO] Starting Flask server to handle CID attachment(s) file(s) for PDF processing.\033[0m")
                server_thread = Thread(target=run_server, daemon=True)
                server_thread.start()
                # time.sleep(1)
                try:
                    wait_for_flask(PORT)
                    server_flask_started = True
                    html_content = replace_src_with_url(html_content, attachments_files, PORT)
                except Exception as e:
                    print(f"[ERROR] Could not start Flask server: {e}")
                    server_flask_started = False
        else:
            html_content = "The message contains neither plain text nor HTML."

        file_safe_subject = subject.replace("/", "-").replace("\\", "-").replace(":", "-").replace("*", "-").replace("+", "-").replace("é", "e").replace("à", "a")
        # print(f"file_safe_subject: {file_safe_subject}")
        final_pdf_path = os.path.join(save_dir, f"{file_safe_subject}.pdf")
        # print(f"final_pdf_path: {final_pdf_path}")

        try:
            with sync_playwright() as p:
                try:
                    def has_dynamic_content(html_content):
                        dynamic_patterns = {
                            "script tags": r"<script.*?>.*?</script>",  # Detection of <script> tags
                            "iframe tags": r"<iframe.*?>.*?</iframe>",  # Detection of <iframe> tags
                            "JS frameworks (React/Vue/Angular)": r"data-reactroot|ng-app|vue",  # Detection of JS frameworks like React, Vue, or Angular
                            "AJAX calls": r"XMLHttpRequest|fetch",  # AJAX calls via XMLHttpRequest or fetch
                            "Media queries": r"@media",  # CSS media queries for dynamic styling
                            "CSS transitions/animations": r"transition|animation",  # Detection of CSS transitions or animations
                            "JavaScript timers": r"setInterval|setTimeout",  # Detection of JavaScript timers (setInterval, setTimeout)
                            "AJAX content markers": r"data-ajax",  # Markers for AJAX calls in HTML data (e.g., data-ajax="true")
                            "Vue.js or React markers": r"v-bind|v-for|data-v-",  # Detection of Vue.js (specific markers) or React
                            "WebSocket indicators": r"WebSocket",  # Detection of WebSocket (indicator of real-time dynamic content)
                            "Dynamic event listeners": r"addEventListener",  # Detection of dynamic JavaScript event listener additions
                            "Inline CSS for dynamic styles": r"style=['\"].*?display\s*:\s*none.*?['\"]",  # Inline CSS styles for dynamic elements (e.g., display: none)
                            "Loading indicators": r'loading|lazy|spinner|progress',  # Detection of loading elements like "lazy", "loading", "spinner", "progress"
                            "Dynamic data attributes": r"data-\w+",  # Detection of dynamic data attributes (e.g., data-id, data-src)
                            "Content injected by JavaScript": r"document\.write|innerHTML|outerHTML",  # Detection of content injected by JS
                            "MutationObserver": r"MutationObserver",  # Detection of MutationObserver usage (used to detect DOM changes)
                            "IntersectionObserver": r"IntersectionObserver",  # Detection of IntersectionObserver usage for elements appearing in view
                            "Lazy-loaded content": r"data-src|data-lazy",  # Detection of lazy-loaded content
                            "Viewport-related dynamic elements": r"viewport|resize",  # Dynamic elements related to the viewport (e.g., during window resizing)
                            "SVG graphics": r"<svg",  # Detection of SVG graphics often dynamically manipulated via JavaScript
                            "Web components": r"<\w+-\w+",  # Detection of custom web components (e.g., <my-component>)
                            "Dynamic background images": r"background-image\s*:\s*url",  # Detection of background images often changed dynamically
                        }

                        for desc, pattern in dynamic_patterns.items():
                            if re.search(pattern, html_content, re.IGNORECASE):
                                print(f"Dynamic content detected: Found {desc}")
                                return True

                        return False

                    # Check if dynamic content exists
                    headless_mode = not has_dynamic_content(html_content)
                    print(f"headless_mode: {headless_mode}")

                    browser = p.chromium.launch(headless=headless_mode)
                    page = browser.new_page()
                    page.set_content(html_content, timeout=60000)  # Set content to the page

                    # browser = p.chromium.launch(headless=False) # `headless=False` to show the interface
                    # page = browser.new_page()
                    # page.set_content(html_content, timeout=30000)

                    if server_flask_started:
                        images = page.query_selector_all('img[src^="http://127.0.0.1"]')
                        for img in images:
                            page.wait_for_function('img => img.complete && img.naturalHeight !== 0', arg=img, timeout=10000)

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
                    contains_pdf = any(file.lower().endswith('.pdf') for file in attachments_files)
                    if attachments_files:
                        url_pattern = re.compile(r'http://127.0.0.1:\d+/(.+?\.(jpg|png|gif|jpeg))')
                        urls_in_html = re.findall(url_pattern, html_content)
                        has_matching_files = any(url[0] in attachments_files for url in urls_in_html)
                        if server_flask_started and has_matching_files:
                            if contains_pdf:
                                footer_template = """
                                    <div style="font-size: 10px; color: #666; text-align: center; width: 100%">
                                        {attachments_html_pdf}
                                        <span class="pageNumber"></span> / <span class="totalPages"></span>
                                    </div>
                                """.format(attachments_html_pdf=attachments_html_pdf)
                            else:
                                footer_template = """
                                    <div style="font-size: 10px; color: #666; text-align: center; width: 100%">
                                        <span class="pageNumber"></span> / <span class="totalPages"></span>
                                    </div>
                                """
                        else:
                            footer_template = """
                                <div style="font-size: 10px; color: #666; text-align: center; width: 100%">
                                    {attachments_html}
                                    <span class="pageNumber"></span> / <span class="totalPages"></span>
                                </div>
                            """.format(attachments_html=attachments_html)
                    else:
                        footer_template = """
                            <div style="font-size: 10px; color: #666; text-align: center; width: 100%">
                                {attachments_html}
                                <span class="pageNumber"></span> / <span class="totalPages"></span>
                            </div>
                        """.format(attachments_html=attachments_html)

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
                    print(f"Playwright error during PDF generation: {e}")
                    raise
        except Exception as e:
            print(f"[ERROR] Unexpected error during PDF generation for message {msg_id}: {e}")
            raise
        finally:
            if server_flask_started:
                if 'html_content' in locals() and re.search(r'http://127.0.0.1:\d+/.+?\.jpg|\.png|\.gif|\.jpeg', html_content):
                    delete_matching_attachments(html_content, attachments_files, DOWNLOAD_PATH)
                try:
                    response = requests.post(f"http://127.0.0.1:{PORT}/shutdown")
                    if response.status_code == 200:
                        print("[INFO] Server Flask has been successfully stopped (HTTP 200).")
                    else:
                        print("[ERROR] Server Flask shutdown failed with status code:", response.status_code)
                except requests.exceptions.RequestException as e:
                    print(f"[ERROR] Error during Flask shutdown request: {e}")

        print(f"\033[36m[INFO] PDF document saved for message ID {msg_id} at {DOWNLOAD_PATH}\033[0m")
        now = datetime.now()
        timestamp = now.strftime("%y%m%d_%H%M%S")
        milliseconds = now.microsecond // 1000
        new_pdf_path = os.path.join(save_dir, f"{timestamp}{milliseconds}_{file_safe_subject}.pdf")
        os.rename(final_pdf_path, new_pdf_path)
        print(f"\033[34m  - {os.path.basename(new_pdf_path)}\033[0m")
        print(f"\033[92m[INFO] Finished saving email and attachment(s) for message ID {msg_id}\033[0m\n")
    else:
        print(f"No HTML content found for message {msg_id}.")


def main():
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
            if len(messages) == 1:
                print(f"[INFO] Processing 1 email with label 'HasAttachment' for PDF generation\n")
            elif len(messages) > 1:
                print(f"[INFO] Processing {len(messages)} emails with label 'HasAttachment' for PDF generation\n")
            if len(messages) > 0:

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
