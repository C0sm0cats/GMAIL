import os
import base64
from weasyprint import HTML
from datetime import datetime
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from tzlocal import get_localzone
from email.utils import parsedate_to_datetime
import pytz

SCOPES = ["https://mail.google.com/"]
# SCOPES = ["https://www.googleapis.com/auth/gmail.readonly", "https://www.googleapis.com/auth/gmail.modify"]

DOWNLOAD_PATH = '/your_download_path/'  # Replace this line with your own download path


def get_real_date(date_string):
    if date_string == 'No Date':
        return date_string

    try:
        # Attempt to parse the date with the specific format YYYY.MM.DD-HH.MM.SS.
        parsed_date = datetime.strptime(date_string, '%Y.%m.%d-%H.%M.%S')
    except ValueError:
        # If the specific format fails, try with the standard format.
        try:
            parsed_date = parsedate_to_datetime(date_string)
        except ValueError:
            parsed_date = None

    if parsed_date:
        # Convert the date to the user's local time
        local_tz = get_localzone()
        local_date = parsed_date.astimezone(local_tz)
        # Format the date according to a specific format
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
                print(f"Access Token: {creds.token}")
                print(f"Refresh Token: {creds.refresh_token}")
                print("Expiry:", convert_expiry_to_local_time(creds.expiry))
            except Exception as e:
                print(f"Error refreshing token: {e}")
                flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
                creds = flow.run_local_server(port=0)
                print("New authorization:")
                print(f"Access Token: {creds.token}")
                print(f"Refresh Token: {creds.refresh_token}")
                print("Expiry:", convert_expiry_to_local_time(creds.expiry))
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)
            print("New authorization:")
            print(f"Access Token: {creds.token}")
            print(f"Refresh Token: {creds.refresh_token}")
            print("Expiry:", convert_expiry_to_local_time(creds.expiry))

        with open(token_path, "w") as token:
            token.write(creds.to_json())
    else:
        print("Existing token:")
        print(f"Access Token: {creds.token}")
        print(f"Refresh Token: {creds.refresh_token}")
        print("Expiry:", convert_expiry_to_local_time(creds.expiry))

    return creds


def decode_base64(data):
    missing_padding = 4 - len(data) % 4
    if missing_padding:
        data += '=' * missing_padding
    return base64.urlsafe_b64decode(data)


def save_attachments(service, user_id, msg_id, save_dir):
    message = service.users().messages().get(userId=user_id, id=msg_id).execute()
    parts = message['payload'].get('parts', [])
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

            now = datetime.now().strftime("%y%m%d_%H%M%S")
            new_filename = f"{now}_{filename}"
            new_path = os.path.join(save_dir, new_filename)
            os.rename(path, new_path)
            print(f"Attachment {filename} renamed to {new_filename}.")


def create_combined_html(subject, date, fro, to, cc, html_content, attachments_files):
    attachments_html = ""
    if attachments_files:
        filtered_attachments = [attachment for attachment in attachments_files if attachment]

        if filtered_attachments:
            attachments_html = "<div>Attachments :</div>\n"
            attachments_html += "<ul>\n"
            for attachment in filtered_attachments:
                attachments_html += f"  <li><h6>{attachment}</h6></li>\n"
            attachments_html += "</ul>\n"

    combined_html = f"""
    <html>
    <head>
        <meta charset="UTF-8">
    </head>
    <body>
        <h3 style='margin-top: 10px;'>{subject}</h3>
        <hr>
        <div>De : {fro}</div>
        <div>à : {to}</div>
        <div>Cc : {cc}</div>
        <div>Date : {date}</div>
        <hr>
        <div>{html_content}</div>
        <hr>
        {attachments_html}
    </body>
    </html>
    """
    return combined_html


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
                # Split name and email address
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
                # Split name and email address
                if '<' in to and '>' in to:
                    to_name, to_email = to.split('<', 1)
                    to_email = to_email.rstrip('>')
                    to_email = f" {to_email}"
                    to = f"{to_name.strip()} {to_email.strip()} "
                # break

            if header['name'] == 'Cc':
                cc = header['value']
                # Sépare les adresses e-mails si plusieurs sont présentes
                cc_list = []
                for email in cc.split(','):
                    email = email.strip()
                    if '<' in email and '>' in email:
                        cc_name, cc_email = email.split('<', 1)
                        cc_email = cc_email.rstrip('>')  # Supprime le chevron angulaire à la fin
                        cc_email = f" {cc_email}"
                        cc_list.append(f"{cc_name.strip()} {cc_email.strip()}")
                    else:
                        cc_list.append(email.strip())
                cc = ', '.join(cc_list)  # Recombine les adresses dans le format attendu

            # On arrête la boucle après avoir traité les deux champs
            if to and cc:  # On vérifie si les deux sont récupérés
                break

    parts = message.get('payload', {}).get('parts', [])

    def extract_parts(parts):
        for part in parts:
            mime_type = part.get('mimeType')
            if mime_type == 'text/html':
                if part.get('body') and part['body'].get('data'):
                    return part['body']['data']
            elif mime_type == 'text/plain':
                if part.get('body') and part['body'].get('data'):
                    return part['body']['data']
            elif mime_type == 'multipart/alternative':
                return extract_parts(part.get('parts', []))
            elif mime_type == 'multipart/related':
                return extract_parts(part.get('parts', []))
            print(f"Found part with MIME type: {mime_type}")
        return ""

    attachments_files = []

    if 'body' in payload and 'data' in payload['body']:
        data = payload['body']['data']
    else:
        data = extract_parts(parts)

    if data:
        html_content = decode_base64(data).decode('utf-8')

        if 'payload' in message:
            payload = message['payload']
            if 'parts' in payload:
                for part in payload['parts']:
                    if 'filename' in part:
                        attachments_files.append(part['filename'])

        combined_html = create_combined_html(subject, date, fro, to, cc, html_content, attachments_files)

        file_safe_subject = subject.replace("/", "-").replace("\\", "-").replace(":", "-").replace("*", "-").replace("+", "-")

        final_pdf_path = os.path.join(save_dir, f"{file_safe_subject}.pdf")

        HTML(string=combined_html).write_pdf(final_pdf_path)

        print(f"Email {msg_id} saved as PDF at {final_pdf_path}.")

        now = datetime.now().strftime("%y%m%d_%H%M%S")
        new_pdf_path = os.path.join(save_dir, f"{now}_{file_safe_subject}.pdf")
        os.rename(final_pdf_path, new_pdf_path)
        print(f"PDF file renamed to {os.path.basename(new_pdf_path)}.")

    else:
        print(f"No HTML content found for message {msg_id}.")

    save_attachments(service, user_id, msg_id, save_dir)


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
            print(f"Number of emails retrieved: {len(messages)}")

            if len(messages) > 0:
                for message in messages:
                    msg_id = message["id"]
                    save_email_and_attachments(service, user_id, msg_id, DOWNLOAD_PATH)

                print(f"{len(messages)} emails and their attachments have been saved in {DOWNLOAD_PATH}.")

                for message in messages:
                    msg_id = message["id"]
                    service.users().messages().modify(userId=user_id, id=msg_id, body={"removeLabelIds": [label_id]}).execute()
                    service.users().messages().modify(userId=user_id, id=msg_id, body={"addLabelIds": [label_name_processed_id]}).execute()
                    # Delete email
                    # service.users().messages().delete(userId=user_id, id=msg_id).execute()

                print(f"The label of processed emails has been changed to '{label_name_processed}'.")
            else:
                print("No emails to process with the label '{}'.".format(label_name))
        else:
            print(f"Label '{label_name}' not found.")

    except HttpError as error:
        print(f"An error occurred: {error}")


if __name__ == "__main__":
    main()
