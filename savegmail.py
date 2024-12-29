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
import pytz
import re

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
                print("Token refreshed:")
                print("Expiry:", convert_expiry_to_local_time(creds.expiry))
            except Exception as e:
                print(f"Error refreshing token: {e}")
                flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
                creds = flow.run_local_server(port=0)
                print("Expiry:", convert_expiry_to_local_time(creds.expiry))
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)
            print("Expiry:", convert_expiry_to_local_time(creds.expiry))
        with open(token_path, "w") as token:
            token.write(creds.to_json())
    return creds


def decode_base64(data):
    missing_padding = 4 - len(data) % 4
    if missing_padding:
        data += '=' * missing_padding
    return base64.urlsafe_b64decode(data)


def save_attachments(service, user_id, msg_id, save_dir, attachments_files):
    message = service.users().messages().get(userId=user_id, id=msg_id).execute()
    parts = message['payload'].get('parts', [])
    attachments_html = ""
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
        print(f"\033[36m1 Attachment saved :\033[0m")
        print(f"\033[34m{attachments_files[0]}\033[0m")
    elif len(attachments_files) > 1:
        print(f"\033[36m{len(attachments_files)} Attachments saved :\033[0m")
        for file in attachments_files:
            print(f"\033[34m{file}\033[0m")
    else:
        print(f"\033[34mNo attachments to save.\033[0m")

    if attachments_files:
        filtered_attachments = [attachment for attachment in attachments_files if attachment]
        if filtered_attachments:
            attachments_html = "<div>Attachments :</div>\n"
            attachments_html += "<ul style='list-style-type: none; padding: 0; margin: 0;'>\n"
            for attachment in filtered_attachments:
                attachment_path = os.path.join(DOWNLOAD_PATH, attachment)
                attachment_url = f"file://{os.path.abspath(attachment_path)}"
                attachments_html += f"  <li style='margin-bottom: 0;'><h6 style='margin: 0; padding: 0;'><a href='{attachment_url}'>{attachment}</a></h6></li>\n"
            attachments_html += "</ul>\n"
    else:
        attachments_html = "<div>No Attachments for this mail</div>"
    return attachments_html

def save_email_and_attachments(service, user_id, msg_id, save_dir):
    message = service.users().messages().get(userId=user_id, id=msg_id, format="full").execute()

    # print(f"Message : {message}")

    # payload = message.get('payload', {})
    # print(f"Payload : {payload}")

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
                # break

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

    def extract_parts(parts):
        valid_mime_types = ['text/html', 'text/plain', 'multipart/alternative', 'multipart/related' , 'multipart/mixed']
        mime_type = None
        data = ""
        html_data = None
        plain_data = None
        for part in parts:
            mime_type = part.get('mimeType')
            if mime_type in valid_mime_types:
                if part.get('body') and part['body'].get('data'):
                    if mime_type == 'text/html':
                        html_data = part['body']['data']
                    elif mime_type == 'text/plain':
                        plain_data = part['body']['data']
                elif 'parts' in part:
                    html_data, plain_data = extract_parts(part['parts'])
        if html_data:
            return html_data, 'text/html'
        if plain_data:
            return plain_data, 'text/plain'
        return data, mime_type

    attachments_files = []
    attachments_html = save_attachments(service, user_id, msg_id, save_dir, attachments_files)

    if 'body' in payload and 'data' in payload['body']:
        data = payload['body']['data']
        mime_type = payload.get('mimeType', '')
    else:
        data, mime_type = extract_parts(parts)

    if data:
        if mime_type == 'text/plain':
            html_content = decode_base64(data).decode('utf-8')
            html_content = re.sub(r'(>>?|>)', r'<br>', html_content)
            html_content = re.sub(r'(On \d{2}/\d{2}/\d{4})', r'<br><br><hr>\1', html_content)
            date_regex = r'((Le|The) \d{1,2} (janv\.|févr\.|mars\.|avr\.|mai\.|juin\.|juil\.|août\.|sept\.|oct\.|nov\.|déc\.|Jan\.|Feb\.|Mar\.|Apr\.|May\.|Jun\.|Jul\.|Aug\.|Sep\.|Oct\.|Nov\.|Dec\.) \d{4}( (à|at) \d{1,2}:\d{2})?)'
            html_content = re.sub(date_regex, r'<hr>\1', html_content)
        elif mime_type == 'text/html':
            html_content = decode_base64(data).decode('utf-8')
        else:
            html_content = "The message contains neither plain text nor HTML."

        file_safe_subject = subject.replace("/", "-").replace("\\", "-").replace(":", "-").replace("*", "-").replace("+", "-")

        final_pdf_path = os.path.join(save_dir, f"{file_safe_subject}.pdf")

        with sync_playwright() as p:
            try:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.set_content(html_content)

                header_template = """
                    <div style="font-size: 10px; color: #666; text-align: center; width: 100%">
                        <h3 style='margin-top: 0px;'>{subject}</h3>
                        <div>From : {fro}</div>
                        <div>To : {to}</div>
                        <div>Cc : {cc}</div>
                        <div>Date : {date}</div>
                    </div>
                """.format(fro=fro, to=to, cc=cc, date=date, subject=subject)

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
                    margin={
                        "top": "150px",
                        "bottom": "150px",
                        "left": "0",
                        "right": "0",
                    },
                    path=final_pdf_path
                )

                browser.close()
                print(f"The PDF has been saved in {final_pdf_path}")
            except Exception as e:
                print(f"Playwright error during PDF generation : {e}")

        print(f"\033[36mEmail saved :\033[0m")
        now = datetime.now()
        timestamp = now.strftime("%y%m%d_%H%M%S")
        milliseconds = now.microsecond // 1000
        new_pdf_path = os.path.join(save_dir, f"{timestamp}{milliseconds}_{file_safe_subject}.pdf")
        os.rename(final_pdf_path, new_pdf_path)
        print(f"\033[34m{os.path.basename(new_pdf_path)}\033[0m")

    else:
        print(f"No HTML content found for message {msg_id}.")


def main():
    creds = authenticate()
    try:
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
                print(f"\033[36m1 email retrieved.\033[0m")
            elif len(messages) > 1:
                print(f"\033[36m{len(messages)} emails retrieved.\033[0m")
            if len(messages) > 0:
                for message in messages:
                    msg_id = message["id"]
                    save_email_and_attachments(service, user_id, msg_id, DOWNLOAD_PATH)

                for message in messages:
                    msg_id = message["id"]
                    service.users().messages().modify(userId=user_id, id=msg_id, body={"removeLabelIds": [label_id]}).execute()
                    service.users().messages().modify(userId=user_id, id=msg_id, body={"addLabelIds": [label_name_processed_id]}).execute()
                    #service.users().messages().delete(userId=user_id, id=msg_id).execute()
            else:
                print("No emails to process with the label '{}'.".format(label_name))
        else:
            print(f"Label '{label_name}' not found.")

    except HttpError as error:
        print(f"An error occurred: {error}")


if __name__ == "__main__":
    main()
