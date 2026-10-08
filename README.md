# GMAIL - Email and Attachment Backup

SaveGmail is a Python script for archiving Gmail messages as PDFs and saving their attachments locally. It uses the Gmail API for email access and Playwright/Chromium for PDF generation.

## Key Features

- Interactive terminal picker: arrow keys, space to select, `/` to filter, `m` to load older emails, `?` for help
- Views switched with `Tab`: All mail, Inbox, Archived, Starred, Sent, Drafts, Spam, Trash (`R` restores from the trash, marks as not spam, or moves back to the Inbox)
- Archive (`e`), like Gmail, undoable
- Compact, borderless list, newest first, Gmail-style: date and time (time only for today), unread in bold, ★ starred, 📎 attachments, `Draft` / `Sent · <recipient>` instead of yourself as sender, size of big emails, Gmail category and your own labels before the snippet
- Star / unstar (`*`) and open in Gmail (`o`) from the list
- Header shows how many emails are loaded out of Gmail's estimate for the query
- `r` refreshes the list with emails received during the session
- Session workflow: the list comes back after each action, with its result on top
- PDF preview of any email, rendered exactly as it would be saved, without saving anything
- Saves selected emails as PDFs with complete metadata, plus their attachments; inline images are embedded
- Then moves them to the Gmail trash, or keeps them in Gmail
- Trash without saving, delete permanently, or empty the whole trash, with confirmations
- Undo of the last trash or save (restores emails, removes the saved files)
- Renders in headless Chromium, waiting for lazy-loaded images and web fonts
- Live progress with a per-email ✓/✗ line and a session summary
- Failed emails stay in Gmail and leave no partial files behind
- Secure OAuth 2.0 authentication, with a browser sign-in when the session expires
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

The script lists your Gmail messages (newest first) in an interactive picker, starting with the **All mail** view: every email except spam and trash (received, sent, archived, drafts), like Gmail's "All mail". `Tab` / `Shift+Tab` switch between the views shown in the header; each keeps its own list, selection and cursor, and with `--query` every view is filtered by it.

**Archived** is not a Gmail folder or label: Gmail archives an email by removing it from the Inbox, and it stays in All mail. This view lists those emails (All mail minus Inbox, Sent and Drafts).

```text
 All mail  Inbox  Archived  Starred  Sent  Drafts  Spam  Trash  · 50 of ~1,240 emails · newest first   1 selected
         Date              From / To       Subject                    Preview
   ○ ★📎 12:31             Free            Votre facture Freebox      12 MB · Factures · Consultez…
 ❯ ●     09:14             Sent · Paul     Photos du week-end         Voici les photos…
   ○     5 Sep 08:02       Draft           Re: roofing quote          OK for Thursday, I'll come…
   ○     2025-08-31 18:02  LinkedIn        Davy shared a post         Social · Last Tuesday was…

 browse  ↑↓ move · space select · a all · / filter · m more · r refresh · Tab views · ? help · q quit
 email   p preview · o open in Gmail · * star · e archive · enter save+trash · s save+keep
 delete  d trash · D delete permanently · T empty trash
```

Actions apply to the selected emails, or to the current one if none is selected. Selected emails hidden by a `/` filter still count: the header and the `d` / `D` confirmations show how many are hidden. Press `?` in the list for the same key help.

| Key | Action |
| --- | --- |
| `↑` `↓` / `j` `k`, `PgUp` `PgDn`, `Home` `End` | Move |
| `space` | Select / unselect the current email |
| `a` | Select / unselect all visible emails |
| `Tab` / `Shift+Tab` | Next / previous view: All mail, Inbox, Archived, Starred, Sent, Drafts, Spam, Trash |
| `/` | Filter by sender, subject, category or label, e.g. `/promo`, `/draft`, `/sent`, `/factures` (`enter` to apply, `esc` to clear) |
| `m` | Load older emails (added at the bottom) |
| `r` | Refresh: add emails received since, drop the ones deleted or moved in Gmail meanwhile |
| `p` | Preview as the exact PDFs a download would produce, opened in your PDF viewer (temporary file, nothing saved to the download folder); asks `y` before opening more than 5 |
| `o` | Open the current email in Gmail, in your browser |
| `*` | Star / unstar in Gmail (stars all, unless all are already starred) |
| `e` | Archive: remove from the Inbox, keep in All mail (not in the Archived, Trash and Spam views) |
| `enter` | Save PDFs + attachments, then move the emails to the Gmail trash |
| `s` | Save PDFs + attachments and keep the emails in Gmail (marked `✓` in the list) |
| `R` | Trash view: restore the emails from the trash (`enter` and `d` are off in that view). Spam view: not spam, back to the Inbox. Archived view: back to the Inbox |
| `d` | Move the selection to the Gmail trash without saving, after a `y` confirmation (recoverable with `u`, or from Gmail for 30 days) |
| `D` | Permanently delete the selection, without going through the trash, after typing `delete` (cannot be undone) |
| `T` | Empty the whole Gmail trash (not only the selection), after typing `empty` (cannot be undone) — same as `--trash` |
| `u` | Undo the last `d`, `enter`, `s` or `e`: restores the emails from the trash or to the Inbox, and removes the files that action saved (`D` and `T` cannot be undone) |
| `?` | Show the key help in the list |
| `q` / `esc` | Quit |

Unread emails are in bold, `★` marks starred emails and `📎` emails with attachments. Drafts show `Draft` in red and sent emails `Sent · <recipient>` (`Sent · me` when sent to yourself) instead of yourself. Emails over 1 MB show their size, and Gmail categories (Promotions, Social, Updates, Forums) and your own labels appear before the snippet, colored: size in yellow, category in blue, labels in green. After each action the list comes back with the result on top, so several batches can be handled in one session.

When the output is not a terminal (pipe, CI), the script falls back to typed selections such as `1,3`, `2-6`, `2-6,8-10`, `all` or `q`. Prefix with `s` to save and keep in Gmail (`s 1,3`), `d` to trash without saving (`d 2-6`, confirmed with `y`), or `D` to delete permanently (`D 2-6`, confirmed by typing `delete`).

### Filter the listed emails

Use Gmail search syntax with `--query`:

```bash
./run-savegmail.sh --query "has:attachment"
./run-savegmail.sh --query "newer_than:30d"
./run-savegmail.sh --query "from:example@example.com"
```

### Emails loaded per page

```bash
./run-savegmail.sh --max 100
```

Press `m` in the list to load older emails, one page at a time.

### Empty Gmail trash manually

```bash
./run-savegmail.sh --trash
```

Permanently deletes everything in the Gmail trash, after showing the number of messages and asking for confirmation, then exits. It is never run automatically; `T` does the same from the list.

### Render in a visible browser window

```bash
./run-savegmail.sh --headed
```

PDFs are rendered in headless Chromium by default. Use `--headed` as a fallback if an email captures badly.

### Show details

```bash
./run-savegmail.sh --verbose
```

Shows sign-in (full sign-in URL, token refresh errors), token, Chromium, MIME parts and PDF rendering details.

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
5. moves the processed Gmail messages to the Gmail trash, in one batch (`enter` only; `s` keeps them in Gmail)

If any step fails, the files written for that email are removed and the email stays in Gmail, so a later retry starts clean.

## Troubleshooting

### Authentication errors

- Verify `credentials.json` exists next to `savegmail.py`
- Check that Gmail API is enabled in Google Cloud Console
- An expired or revoked session opens a browser sign-in automatically; if sign-in keeps failing, remove `token.json` and run the script again

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

## Tests

```bash
.venv/bin/python -m unittest discover -s tests
```

## Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

### Activity

![Alt](https://repobeats.axiom.co/api/embed/b190ab0f74186972651fce8c254740af2387dc97.svg "Repobeats analytics image")

---

Built with ❤️ by C0sm0cats
