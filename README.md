# GMAIL - Email and Attachment Backup

SaveGmail is a Python script for archiving Gmail messages as PDFs and saving their attachments locally. It uses the Gmail API for email access and Playwright/Chromium for PDF generation.

## Key Features

- Interactive terminal picker: arrow keys, space to select, `/` to filter, `m` to load older emails
- Compact, borderless list with sender, subject, preview snippet and mail-client style dates
- Downloads selected emails as PDFs with complete metadata
- Extracts and saves email attachments, embeds inline images
- Renders in headless Chromium, waiting for lazy-loaded images and web fonts
- Live progress with a per-email ✓/✗ line and a final summary
- Failed emails stay in Gmail and leave no partial files behind
- Moves successfully processed Gmail messages to the Gmail trash
- Provides a manual, confirmed option to empty the Gmail trash
- Secure OAuth 2.0 authentication
- Local Playwright/Chromium setup through the launcher

## Prerequisites

- Python 3.9 or higher
- Google Cloud Platform project with Gmail API enabled
- OAuth 2.0 credentials file (`credentials.json`) next to `savegmail.py`

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
   - Download `credentials.json` next to `savegmail.py` (the script finds it there whatever directory you launch it from)

2. **Download directory**

   The default download path is defined in `savegmail.py`:

   ```python
   DOWNLOAD_PATH = '~/GMail/'
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

The script lists your Gmail messages (oldest to newest) in an interactive picker:

```text
 Gmail · 50 emails · oldest → newest

   ○ 📎 2025-08-31  Amazon        Your order has shipped        Hello, your parcel arrives…
 ❯ ●    5 Sep       Jean Dupont   Re: roofing quote             OK for Thursday, I'll come…
   ○    12:31       GitHub        [repo] PR #42 merged          Merged #42 into main.

 ↑↓ move · a all · space select · / filter · m more · p preview · enter save+trash · s save · d trash · q quit   1 selected
```

| Key | Action |
| --- | --- |
| `↑` `↓` / `j` `k`, `PgUp` `PgDn`, `Home` `End` | Move |
| `space` | Select / unselect the current email |
| `a` | Select / unselect all visible emails |
| `/` | Filter by sender or subject (`enter` to apply, `esc` to clear) |
| `m` | Load older emails |
| `p` | Preview the current email (full text, in a pager) |
| `enter` | Save the selection as PDFs, then move it to the Gmail trash (the current email if none is selected) |
| `s` | Save the selection as PDFs and keep it in Gmail (marked `✓` in the list) |
| `d` | Move the selection to the Gmail trash without saving, after a `y` confirmation |
| `u` | Undo the last move to trash |
| `q` / `esc` | Quit |

`📎` marks emails with attachments. After each action the list comes back with the result on top, so several batches can be handled in one session.

When the output is not a terminal (pipe, CI), the script falls back to typed selections such as `1,3`, `2-6`, `2-6,8-10`, `all` or `q`. Prefix with `s` to save only (`s 1,3`) or `d` to trash without saving (`d 2-6`, confirmed with `y`).

After a selected email is successfully saved locally, the script moves the corresponding Gmail message to the Gmail trash (except with `s`).

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

This option only empties the Gmail trash, after showing the number of messages and asking for confirmation. It is not run automatically after downloads.

### Render in a visible browser window

```bash
./run-savegmail.sh --headed
```

PDFs are rendered in headless Chromium by default. Use `--headed` as a fallback if an email captures badly.

### Show details

```bash
./run-savegmail.sh --verbose
```

Shows token, Chromium, MIME parts and PDF rendering details.

### Show help

```bash
./run-savegmail.sh --help
```

## Email Processing

For each selected message, SaveGmail:

1. retrieves the email through the Gmail API
2. extracts metadata such as subject, sender, recipients, and date
3. saves attachments in the configured download directory
4. renders the message body to PDF using headless Chromium, named `<timestamp>_<subject>.pdf`
5. moves the processed Gmail messages to the Gmail trash, in one batch (unless saved with `s`)

If any step fails, the files written for that email are removed and the email stays in Gmail, so a later retry starts clean.

## Troubleshooting

### Authentication errors

- Verify `credentials.json` exists next to `savegmail.py`
- Check that Gmail API is enabled in Google Cloud Console
- If the OAuth token is invalid, remove `token.json` and run the script again

### Download issues

- Check destination directory permissions
- Ensure sufficient disk space
- Use `--download-path` to test another output directory

### PDF rendering

- If an email renders badly, retry it with `--headed`
- Use `--verbose` to see which MIME parts and inline images were processed

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

## Tests

```bash
.venv/bin/python -m unittest discover -s tests
```
