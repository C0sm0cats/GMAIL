# GMAIL

SaveGmail is a Python script that allows you to download emails and their attachments from Gmail, and save them as PDF files. It provides functionalities to authenticate with Gmail using OAuth 2.0, retrieve emails with specific labels, save email content as PDF, and save attachments to a specified directory.

## Prerequisites

Before using SaveGmail, make sure you have the following:
- Python installed on your system (version 3.6 or higher)
- Google Cloud Platform project with Gmail API enabled
- OAuth 2.0 credentials file (`credentials.json`) downloaded from the Google Cloud Console
- Dependencies installed (`base64`, `weasyprint`, `datetime`, `google-auth`, `google-auth-oauthlib`, `google-api-python-client`, `pytz`)
- Gmail labels `HasAttachment` and `HasAttachment/SavedAsPDF` created in your Gmail account
- A Gmail filter rule set up to apply the `HasAttachment` label to emails with attachments

For more detailed information on setting up and running an app that calls a Google Workspace API, visit the [Google Gmail API Quickstart guide](https://developers.google.com/gmail/api/quickstart/python).

## Usage

1. Clone this repository to your local machine.

    ```bash
    git clone https://github.com/C0sm0cats/GMAIL.git
    ```

2. Replace the value of `DOWNLOAD_PATH` variable in the script (`savegmail.py`) with your desired download directory.

3. Run the script.

    ```bash
    python savegmail.py
    ```

4. Follow the instructions in the terminal to authenticate with your Gmail account and start downloading emails and attachments.

## Notes

- This script requires OAuth 2.0 credentials to access the Gmail API. Make sure to set up the credentials file (`credentials.json`) correctly.
- Ensure that the specified download directory (`DOWNLOAD_PATH`) exists and has write permissions.

### Label Usage

SaveGmail utilizes Gmail labels to manage the processing of emails. Before running the script, make sure to set up the following labels in your Gmail account:
- **HasAttachment**: This label is applied to emails that contain attachments.
- **HasAttachment/SavedAsPDF**: Once the attachments are saved as PDFs, the script will move the processed emails to this label.

### Changing Labels in Gmail

The script automatically changes the labels of processed emails to keep track of their status. It removes the `HasAttachment` label and adds the `HasAttachment/SavedAsPDF` label to indicate that the attachments have been saved. This helps in organizing your emails within Gmail.

### Activity

![Alt](https://repobeats.axiom.co/api/embed/b190ab0f74186972651fce8c254740af2387dc97.svg "Repobeats analytics image")