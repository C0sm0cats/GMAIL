# GMAIL - Email and Attachment Backup

SaveGmail is a Python script for archiving Gmail messages as PDFs and saving their attachments locally. It uses the Gmail API for email access and Playwright/Chromium for PDF generation.

## Key Features

- Lists available Gmail messages directly in the terminal
- Lets you choose emails interactively by number, ranges, or multiple ranges
- Downloads selected emails as PDFs with complete metadata
- Extracts and saves email attachments
- Preserves HTML email formatting where possible
- Moves successfully processed Gmail messages to the Gmail trash
- Provides a manual option to empty the Gmail trash
- Secure OAuth 2.0 authentication
- Local Playwright/Chromium setup through the launcher

## Prerequisites

- Python 3.6 or higher
- Google Cloud Platform project with Gmail API enabled
- OAuth 2.0 credentials file (`credentials.json`) in the project directory

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/C0sm0cats/GMAIL.git
   cd GMAIL
   ```

2. Make the launcher executable if needed:
   ```bash
   chmod +x run-savegmail.sh
   ```

3. Run the launcher once to bootstrap the local Python environment:
   ```bash
   ./run-savegmail.sh --help
   ```

   The launcher creates a local `.venv` when it is missing, installs the Python dependencies, and installs the Playwright Chromium browser binaries inside that virtual environment.

## Configuration

1. **Google Cloud Platform setup**
   - Create a project on [Google Cloud Console](https://console.cloud.google.com/)
   - Enable Gmail API
   - Create OAuth 2.0 credentials
   - Download `credentials.json` to the project directory

2. **Download directory**

   The default download path is defined in `savegmail.py`:

   ```python
   DOWNLOAD_PATH = '~/Downloads/'
   ```

   You can either change that variable in the script or override it at runtime:

   ```bash
   ./run-savegmail.sh --download-path /path/to/archive/
   ```

## Usage

### Interactive download

Run:

```bash
./run-savegmail.sh
```

By default, the script lists Gmail messages without requiring the old `HasAttachment` label workflow. You then select which messages to download from the terminal.

Supported selections:

```text
1,3,5      numbers separated by commas or spaces
2-6        number range
2-6,8-10   multiple ranges
1,3,7-9    mix of numbers and ranges
all        select everything listed
q          quit without downloading
```

After a selected email is successfully saved locally, the script moves the corresponding Gmail message to the Gmail trash.

### Filter the listed emails

Use Gmail search syntax with `--query`:

```bash
./run-savegmail.sh --query "has:attachment"
./run-savegmail.sh --query "newer_than:30d"
./run-savegmail.sh --query "from:example@example.com"
```

### Limit the number of listed emails

```bash
./run-savegmail.sh --max 100
```

### Empty Gmail trash manually

```bash
./run-savegmail.sh --trash
```

This option only empties the Gmail trash. It is not run automatically after downloads.

### Show help

```bash
./run-savegmail.sh --help
```

## Email Processing

For each selected message, SaveGmail:

1. retrieves the email through the Gmail API
2. extracts metadata such as subject, sender, recipients, and date
3. renders the message body to PDF using Playwright/Chromium
4. saves attachments in the configured download directory
5. moves the processed Gmail message to the Gmail trash

## Troubleshooting

### Authentication errors

- Verify `credentials.json` exists in the project directory
- Check that Gmail API is enabled in Google Cloud Console
- If the OAuth token is invalid, remove `token.json` and run the script again

### Download issues

- Check destination directory permissions
- Ensure sufficient disk space
- Use `--download-path` to test another output directory

### Playwright browser setup

- Use `./run-savegmail.sh` instead of running `python savegmail.py` directly
- The launcher keeps Playwright, its bundled driver runtime, and its Chromium browser binaries inside the local `.venv`

## Notes

The older `HasAttachment` / `HasAttachment/SavedAsPDF` Gmail label workflow is no longer required by the current interactive version. If needed, you can still list only attachment-bearing emails with:

```bash
./run-savegmail.sh --query "has:attachment"
```

## Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

### Activity

![Alt](https://repobeats.axiom.co/api/embed/b190ab0f74186972651fce8c254740af2387dc97.svg "Repobeats analytics image")

---

Built with ❤️ by C0sm0cats
