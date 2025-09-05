# GMAIL - Email and Attachment Backup

SaveGmail is a powerful Python script designed to backup emails and attachments from Gmail. It provides a complete solution for archiving and organizing your important emails.

## Key Features

- Download emails with complete metadata
- Extract and save email attachments
- Secure OAuth 2.0 authentication
- Automatic file organization
- Precise timezone handling
- Gmail label management
- Intuitive command-line interface

## Prerequisites

- Python 3.6 or higher
- Google Cloud Platform project with Gmail API enabled
- OAuth 2.0 credentials file (`credentials.json`)
- Gmail account with required labels

## Installation

1. Clone the repository :
   ```bash
   git clone https://github.com/C0sm0cats/GMAIL.git
   ```

2. Install dependencies :
   - `playwright` for browser automation
   - `google-auth` and `google-api-python-client` for Gmail API
   - `pytz` and `tzlocal` for timezone handling
   - `python-dateutil` for date processing
   - `email.parser.BytesParser` for email parsing (included in Python standard library)

## Configuration

1. **Google Cloud Platform Setup**
   - Create a project on [Google Cloud Console](https://console.cloud.google.com/)
   - Enable Gmail API
   - Create OAuth 2.0 credentials
   - Download `credentials.json` to the project directory

2. **Gmail Labels Setup**
   Create these labels in your Gmail account :
   - `HasAttachment` (for emails with attachments to process)
   - `HasAttachment/SavedAsPDF` (where processed emails will be moved)

## Usage

1. **Download Directory Setup**
   Modify the `DOWNLOAD_PATH` variable in the script if needed (default : `~/Downloads/`)

2. **Run the Script**
   ```bash
   python savegmail.py
   ```

3. **Authentication**
   - Follow terminal instructions
   - Authorize the app to access your Gmail account
   - The script handles token refresh automatically

## Advanced Features

### Attachment Handling
- Automatic extraction of all attachment types
- Filename cleaning for compatibility
- Organization in subfolders by sender and date

### Email Management
- Preserved HTML email formatting
- Email to PDF conversion (using Playwright)
- Complete metadata included (From, To, Date, Subject, etc.)

### Error Handling
- Detailed operation logging
- Robust connection error handling
- Resume capability for interrupted downloads

## Customization

You can customize the script's behavior by modifying these variables :
- `SCOPES` : Gmail API permissions
- `DOWNLOAD_PATH` : Download destination directory
- Logging parameters

## Troubleshooting

### Common Issues
1. **Authentication Errors**
   - Verify `credentials.json` exists
   - Check Google Cloud Console permissions

2. **Download Issues**
   - Check destination directory permissions
   - Ensure sufficient disk space

## Contributing

Contributions are welcome ! Feel free to open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

### Activity

![Alt](https://repobeats.axiom.co/api/embed/b190ab0f74186972651fce8c254740af2387dc97.svg "Repobeats analytics image")

---

Built with ❤️ by C0sm0cats