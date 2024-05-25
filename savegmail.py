import os
import base64
import pdfkit
from datetime import datetime
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import pytz

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly", "https://www.googleapis.com/auth/gmail.modify"]

DOWNLOAD_PATH = 'your_download_path'  # Replace this line with your own download path


def convert_expiry_to_paris_time(expiry_utc):
    utc_timezone = pytz.utc
    paris_timezone = pytz.timezone('Europe/Paris')
    expiry_utc = utc_timezone.localize(expiry_utc)
    expiry_paris = expiry_utc.astimezone(paris_timezone)
    return expiry_paris


def authenticate():
    creds = None
    token_path = "token.json"

    if os.path.exists(token_path):
        creds = Credentials.from_authorized_user_file(token_path, SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                print("Token rafraîchi:")
                print(f"Access Token: {creds.token}")
                print(f"Refresh Token: {creds.refresh_token}")
                print("Expiry:", convert_expiry_to_paris_time(creds.expiry))
            except Exception as e:
                print(f"Erreur lors du rafraîchissement du token : {e}")
                flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
                creds = flow.run_local_server(port=0)
                print("Nouvelle autorisation:")
                print(f"Access Token: {creds.token}")
                print(f"Refresh Token: {creds.refresh_token}")
                print("Expiry:", convert_expiry_to_paris_time(creds.expiry))
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)
            print("Nouvelle autorisation:")
            print(f"Access Token: {creds.token}")
            print(f"Refresh Token: {creds.refresh_token}")
            print("Expiry:", convert_expiry_to_paris_time(creds.expiry))

        with open(token_path, "w") as token:
            token.write(creds.to_json())
    else:
        print("Token existant:")
        print(f"Access Token: {creds.token}")
        print(f"Refresh Token: {creds.refresh_token}")
        print("Expiry:", convert_expiry_to_paris_time(creds.expiry))

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
            print(f"Pièce jointe {filename} renommée en {new_filename}.")


def create_combined_html(subject, date, fro, to, html_content, attachments_files):
    attachments_html = ""
    if attachments_files:
        attachments_html = "<h3>Attachments :</h3>"
        attachments_html += "<ul>"
        for attachment in attachments_files:
            attachments_html += f"{attachment}"
        attachments_html += "</ul>"

    combined_html = f"""
    <html>
    <head>
        <meta charset="UTF-8">
    </head>
    <body>
        <h1>{subject}</h1>
        <hr>
        <h3>De : {fro}</h2>
        <h3>à : {to}</h2>
        <h3>Date : {date}</h2>
        <h3>Objet : {subject}</h2>
        <hr>
        {html_content}
        <hr>
        {attachments_html}
    </body>
    </html>
    """
    return combined_html


def save_email_and_attachments(service, user_id, msg_id, save_dir):
    message = service.users().messages().get(userId=user_id, id=msg_id, format="full").execute()

    subject = ""
    if 'payload' in message and 'headers' in message['payload']:
        for header in message['payload']['headers']:
            if header['name'] == 'Subject':
                subject = header['value']
                break

    date_str = ""
    if 'payload' in message and 'headers' in message['payload']:
        for header in message['payload']['headers']:
            if header['name'] == 'Date':
                date_str = header['value']
                break
    date = datetime.strptime(date_str, "%a, %d %b %Y %H:%M:%S %z").strftime("%Y-%m-%d %H:%M:%S")

    fro = ""
    if 'payload' in message and 'headers' in message['payload']:
        for header in message['payload']['headers']:
            if header['name'] == 'From':
                fro = header['value']
                # Sépare le nom et l'adresse e-mail
                if '<' in fro and '>' in fro:
                    fro_name, fro_email = fro.split('<', 1)
                    fro_email = fro_email.rstrip('>')
                    fro_email = f"- {fro_email} -"
                    fro = f"{fro_name.strip()} {fro_email.strip()} "
                break

    to = ""
    if 'payload' in message and 'headers' in message['payload']:
        for header in message['payload']['headers']:
            if header['name'] == 'To':
                to = header['value']
                # Sépare le nom et l'adresse e-mail
                if '<' in to and '>' in to:
                    to_name, to_email = to.split('<', 1)
                    to_email = to_email.rstrip('>')
                    to_email = f"- {to_email} -"
                    to = f"{to_name.strip()} {to_email.strip()} "
                break

    parts = message.get('payload', {}).get('parts', [])

    def extract_parts(parts):
        for part in parts:
            if part.get('mimeType') == 'text/html':
                if part.get('body') and part['body'].get('data'):
                    return part['body']['data']
            elif part.get('mimeType') == 'multipart/alternative':
                return extract_parts(part.get('parts', []))
        return ""

    data = extract_parts(parts)

    attachments_files = []

    if data:
        html_content = decode_base64(data).decode('utf-8')

        if 'payload' in message:
            payload = message['payload']
            if 'parts' in payload:
                for part in payload['parts']:
                    if 'filename' in part:
                        attachments_files.append(part['filename'])

        combined_html = create_combined_html(subject, date, fro, to, html_content, attachments_files)

        file_safe_subject = subject.replace("/", "-").replace("\\", "-").replace(":", "-").replace("*", "-").replace("+", "-")

        final_pdf_path = os.path.join(save_dir, f"{file_safe_subject}.pdf")

        pdfkit.from_string(combined_html, final_pdf_path)

        print(f"Email {msg_id} sauvegardé en tant que PDF à {final_pdf_path}.")

        now = datetime.now().strftime("%y%m%d_%H%M%S")
        new_pdf_path = os.path.join(save_dir, f"{now}_{file_safe_subject}.pdf")
        os.rename(final_pdf_path, new_pdf_path)
        print(f"Fichier PDF renommé en {os.path.basename(new_pdf_path)}.")

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
            print(f"Nombre d'emails récupérés : {len(messages)}")

            if len(messages) > 0:
                for message in messages:
                    msg_id = message["id"]
                    save_email_and_attachments(service, user_id, msg_id, DOWNLOAD_PATH)

                print(f"{len(messages)} emails et leurs pièces jointes ont été sauvegardés dans {DOWNLOAD_PATH}.")

                for message in messages:
                    msg_id = message["id"]
                    service.users().messages().modify(userId=user_id, id=msg_id, body={"removeLabelIds": [label_id]}).execute()
                    service.users().messages().modify(userId=user_id, id=msg_id, body={"addLabelIds": [label_name_processed_id]}).execute()
                    service.users().messages().delete(userId=user_id, id=msg_id).execute()

                print(f"L'étiquette des emails traités a été changée en '{label_name_processed}'.")
            else:
                print("Aucun e-mail à traiter avec l'étiquette '{}'.".format(label_name))
        else:
            print(f"Label '{label_name}' non trouvé.")

    except HttpError as error:
        print(f"Une erreur est survenue : {error}")


if __name__ == "__main__":
    main()
