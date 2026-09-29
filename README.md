# Minecraft JAR Analyzer

**Version 0.1.0** · Publisher: Max · MIT License

A desktop tool that helps **authorized Minecraft server staff** examine
Minecraft mod and plugin JAR files for signs that warrant a closer look.
It is a **static analyzer**: it reads the files as data and never runs them.

> **Intended use:** security review of files you are authorized to examine,
> for example mods submitted to or found on a server you administer. Results are
> *indicators for a human to review*, never proof that a file is malicious or safe.

---

## What it does

- Analyzes one JAR, several JARs, or a whole folder (optionally including subfolders). You can also drag and drop files onto the window.
- Collects **file information**: name, size, SHA-256, modification time, the real file type (from the file's first bytes, not its extension), and whether it is a valid JAR.
- Reads **META-INF/MANIFEST.MF** (Main-Class, Implementation-*, Java agent entries...).
- Takes an **inventory** of the contents: counts by extension, large files, native libraries, executables and scripts, bundled JARs, unusual file types, and files whose content doesn't match their extension.
- Detects **mod metadata** and the loader: Fabric, Quilt, Forge (including legacy `mcmod.info`), NeoForge, and Bukkit/Spigot/Paper plugins. It extracts the mod ID, name, version, description, authors, dependencies, Minecraft version and loader version.
- Parses every **Java class file's constant pool** (the table of classes, methods and strings the code refers to) without executing anything, and uses it to report **security indicators**, including:
  - reflection, dynamic class loading, running external programs, native code, Java agents, JNDI
  - embedded URLs (Discord webhooks, Telegram bots, paste sites, tunnels, raw IPs...)
  - references to credential stores (Discord tokens, browser logins, launcher accounts, crypto wallets)
  - Base64-encoded payloads and hidden URLs
  - obfuscated, confusable or misplaced class names
  - look-alike mod IDs that may impersonate popular mods
  - inconsistent metadata, and duplicate mod IDs across the selected files
  - names associated with gameplay-advantage (cheat) features
- Also analyzes **bundled JARs** (JAR-in-JAR), sharing the same safety budget.
- Looks up each file's **SHA-256** in a local database (`VERIFIED` / `SUSPICIOUS` / `UNKNOWN`).
- Exports complete **JSON** and **TXT** reports.

Every finding has a **severity**, a **title**, a **location**, a plain-English
**explanation** (including legitimate reasons it might appear) and a **confidence**.
REVIEW and WARNING findings also say **what context was found** (what else the
same class does) and **why they got that rating**.

| Severity | Meaning |
|---|---|
| `INFO` | Informational: a fact about the JAR (metadata, bundled libraries, ordinary APIs). Not a security warning. |
| `REVIEW` | Inspect this behavior: a capability with security relevance that legitimate mods also use (running programs, loading native code, runtime class loading...). |
| `WARNING` | Strong security concern: a strong indicator or a *combination* of indicators, such as downloading something and running it in the same class. |

**Confidence** (`LOW` / `MEDIUM` / `HIGH`) says how strongly the evidence shows
the behavior is *security-significant*, not whether the API is present (a static
match is always certain). "Main-Class exists" is a sure fact with no security
weight, so INFO findings show no confidence (`—`). "Runs `xdg-open`" is
REVIEW/LOW; "downloads a `.jar` and starts a hidden PowerShell" is WARNING/HIGH.

## What it does NOT do

- ❌ Execute, load or decompile the analyzed JAR, or launch Java against it
- ❌ Inject into or modify Minecraft
- ❌ Modify, delete, move or quarantine any analyzed file
- ❌ Extract JAR contents to disk (everything is read in memory)
- ❌ Upload anything or make any network connection
- ❌ Collect passwords, cookies, messages or any personal information
- ❌ Output "CHEAT DETECTED" or any other verdict. It reports evidence.

Reports contain only the analyzed file's **name**, never its full path (which
could contain your Windows username).

These guarantees are enforced by automated tests (`tests/test_safety.py`). The
tests scan the source code for process, network, deserialization, extraction and
deletion calls. They also make any attempt to start a process, open a socket or
extract a file fail during analysis, and they verify that the analyzed file is
unchanged afterwards.

---

## Project status

- ✅ Analysis engine, CLI, reports and GUI: implemented and tested on macOS (Python 3.14, PySide6 6.11).
- ✅ The PyInstaller spec builds and the frozen app starts, smoke-tested on macOS only.
- ⏳ **The Windows `.exe` has not been built or tested yet.** Follow
  [Building the Windows .exe](#building-the-windows-exe) and the
  [Windows test checklist](#windows-test-checklist) on a Windows PC.

---

## Development setup

Requires **Python 3.11 or newer** (the code uses `tomllib` and `StrEnum`).

### macOS / Linux

```bash
cd minecraft-jar-analyzer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
```

### Windows (for development)

```bat
cd minecraft-jar-analyzer
py -3 -m venv .venv
.venv\Scripts\activate
pip install -r requirements-dev.txt
```

`requirements.txt` lists what the app needs (only `PySide6-Essentials`).
`requirements-dev.txt` adds `pytest` and `pyinstaller`.

## Running

### The GUI

```bash
python main.py
```

1. Click **Select JAR(s)…** or **Select Folder…**, or drag files onto the window.
2. Click **Analyze**. Analysis runs in the background and you can **Cancel** it.
3. Pick a file under **Results**. The tabs show:
   - **Overview**: file info, SHA-256 (with a copy button), mod info, hash-database result and findings
   - **Findings**: a table of findings. Select one to see why it matters.
   - **Contents**, **Metadata** and **Errors**: the details
4. Click **Export JSON…** or **Export TXT…** to save a report.

### The command-line runner

Useful for learning, debugging and scripting:

```bash
python -m analyzer path/to/mod.jar
python -m analyzer path/to/mods/ --recursive --json report.json --txt report.txt
python -m analyzer path/to/mod.jar --quiet --json report.json
python -m analyzer --help
```

## Running the tests

```bash
python -m pytest            # all tests
python -m pytest -v         # verbose: one line per test
python -m pytest tests/test_jar.py -v   # a single file
```

The tests never execute any JAR. All test JARs are generated in memory by
`tests/conftest.py`, and test class files are hand-assembled bytes
(`tests/classbuilder.py`) with no real code inside.

The suite covers: SHA-256, valid/corrupt/truncated/renamed JARs, bad CRCs,
oversized files, entry-count limits, zip bombs (per entry and total budget),
nested JARs, manifest parsing, Fabric/Quilt/Forge/NeoForge/legacy
Forge/plugin.yml metadata, malformed and deeply nested JSON/TOML, invalid
UTF-8, class-file parsing, every indicator rule (including tests for known
false positives found in real mods), the hash database, JSON/TXT reports, the
CLI, the GUI (off-screen) and the safety guarantees.

---

## Building the Windows .exe

PyInstaller packages the Python and Qt of **the machine it runs on**, so the
Windows `.exe` must be built **on Windows**. (Running PyInstaller on macOS
produces a macOS program, not a Windows one.)

1. On the Windows PC, install **64-bit Python 3.11+** from
   [python.org](https://www.python.org/downloads/windows/). Python 3.13 is a
   good choice. Keep the default "py launcher" option ticked.
2. Copy the whole `minecraft-jar-analyzer` folder to the PC, or clone it.
3. Double-click **`build_windows.bat`**, or run it from a terminal in the project folder.

The script:

1. finds Python
2. creates (or reuses) `.venv`
3. installs the pinned dependencies
4. runs the full test suite, and **stops without building if any test fails**
5. runs PyInstaller with `packaging\Minecraft-JAR-Analyzer.spec`
6. prints the SHA-256 of the finished executable

The result is **`dist\Minecraft-JAR-Analyzer.exe`**, a single file. The target PC needs
no Python, pip, Java or packages.

### Things to know about the .exe

- **Windows SmartScreen:** the `.exe` is **not code-signed**, so on first
  launch Windows may show *"Windows protected your PC"*. Click **More info → Run
  anyway**. Removing this warning requires buying a real code-signing
  certificate. This project does not fake one.
- **Antivirus false positives:** one-file PyInstaller programs are sometimes
  flagged by antivirus heuristics. UPX compression is disabled to reduce this.
  If it happens, you can submit the file to your AV vendor as a false positive.
- **Startup time:** a one-file `.exe` unpacks itself to a temporary folder on
  each launch, so it takes a few seconds to open.
- **Windows file properties** (right-click → Properties → Details) come from
  `packaging/version_info.txt`. Keep it in sync with `analyzer/version.py` when
  you change the version.

### Windows test checklist

Do this on Windows **before** distributing a build. Ideally use a PC or VM
without Python installed.

- [ ] Double-clicking `Minecraft-JAR-Analyzer.exe` opens the window, with no console window.
- [ ] The window and taskbar show the application icon.
- [ ] Properties → Details shows the name, version 0.1.0 and publisher Max.
- [ ] The status bar shows "Hash database: … entries".
- [ ] Select JAR(s), Select Folder (with and without "Include subfolders") and drag-and-drop all work.
- [ ] Analyzing a known-good mod shows sensible metadata and mostly INFO findings.
- [ ] A corrupt file (for example, a `.txt` renamed to `.jar`) shows an error, not a crash.
- [ ] Cancel works during a large folder analysis.
- [ ] Export JSON and Export TXT create files that open correctly (TXT in Notepad).
- [ ] With a `database\hashes.json` placed next to the `.exe`, that file is used.
- [ ] Closing the window during an analysis exits cleanly.

---

## Updating the hash database

The database is `database/hashes.json`:

```json
{
  "schema_version": 1,
  "updated": "2026-09-28",
  "entries": {
    "<the file's SHA-256: 64 hex characters>": {
      "classification": "VERIFIED",
      "name": "Example Mod",
      "version": "1.2.0",
      "source": "Downloaded from the official Modrinth page",
      "notes": "",
      "added": "2026-09-28"
    }
  }
}
```

- Keys are SHA-256 hashes (64 hex characters).
- `classification` must be `VERIFIED`, `SUSPICIOUS` or `UNKNOWN`.
- A file whose hash is **not** listed is shown as **UNKNOWN**. That only means
  "no record of this exact file". It is **not** a sign of malice.
- The database ships **empty on purpose**. Hashes should come from files *you*
  have checked, not from an unverifiable list.
- Invalid entries are skipped with a warning. A broken file produces an error
  message, and analysis continues without the database.

**With the helper script** (from the project folder, with the venv active):

```bash
# Hash a JAR and add it. Name and version are read from its metadata.
python -m tools.add_hash path/to/sodium.jar --classification VERIFIED --source "Official Modrinth page"

# Add a hash directly (for example from an incident report)
python -m tools.add_hash --sha256 <hash> --classification SUSPICIOUS --name "Fake Sodium" --notes "Ticket #42"

python -m tools.add_hash --list
python -m tools.add_hash --remove <hash>
```

The script writes atomically: it saves to a temporary file and then swaps it
in, so a crash can't leave a half-written database.

**For the .exe:** the `.exe` contains a built-in copy of the database. To use an
updated one **without rebuilding**, create a `database` folder **next to
`Minecraft-JAR-Analyzer.exe`** and put your `hashes.json` in it. The app
prefers that copy.

You can also copy a SHA-256 from the **Overview** tab (Copy button) and edit
the JSON by hand.

---

## Security limitations

Please read these before relying on results.

- **Static analysis can be evaded.** Strings built at runtime, encrypted
  payloads, heavy obfuscation or code downloaded later do not appear in the
  constant pool. A file with no findings can still be malicious.
- **Indicators are not verdicts.** Many legitimate mods use reflection,
  networking, native libraries or even run programs (for example to open a
  browser). Legitimate self-updaters that download a JAR and replace
  themselves with a hidden script produce the same WARNINGs as a dropper,
  because statically they do the same thing. Always read the context, the
  explanation and the location.
- **Metadata can lie.** Names, authors and versions in `fabric.mod.json` and
  similar files are written by whoever built the JAR.
- **Only exact files match the hash database.** Changing a single byte
  produces a different SHA-256.
- **JAR signatures are listed but not verified.**
- **Safety limits can leave analysis incomplete.** This is always reported,
  with a finding and an error message.
- **Cheat-feature detection is about server rules, not malware.** It relies on
  names, and some legitimate mods (for example anti-cheat tools) contain the same words.

### Safety limits

All limits live in `analyzer/limits.py`:

| Limit | Default |
|---|---|
| Maximum JAR size | 256 MB |
| Maximum entries per JAR | 50,000 |
| Maximum bytes decompressed from one entry | 32 MB |
| Maximum total bytes decompressed per JAR (bundled JARs included) | 512 MB |
| Maximum metadata file size (JSON/TOML/manifest) | 1 MB |
| Compression ratio reported as suspicious | > 100:1 (entries ≥ 1 MB) |
| Maximum JAR-in-JAR nesting depth | 2 |
| Maximum findings per rule | 50 (the rest are summarized) |

Why they matter: a **zip bomb** is a tiny archive that expands to gigabytes.
The analyzer checks the ZIP structure before parsing it. It decompresses in
64 KB chunks and counts the real bytes as they come out, so it stops as soon
as a limit is crossed, and it never trusts the sizes an archive *claims*.

---

## Architecture

```
main.py ──► gui/app.py ──(QThread)──► analyzer/pipeline.py ──► AnalysisResult ──► reports/exporter.py
                                           │
    jar.py (safe reading) ─ manifest.py ─ metadata.py ─ contents.py ─ classes.py ─ indicators.py
                                           │
                               hash_database.py ─ hashing.py
```

The **analysis engine (`analyzer/`) contains no GUI code**. The GUI, the CLI,
the report exporter and the tests all use the same `analyze_file()` function
and the same `AnalysisResult` dataclass.

```
minecraft-jar-analyzer/
├── main.py                     Entry point (GUI)
├── requirements.txt            Runtime dependency: PySide6-Essentials
├── requirements-dev.txt        + pytest, pyinstaller
├── build_windows.bat           Windows build script
├── analyzer/
│   ├── __main__.py             Command-line runner (python -m analyzer)
│   ├── version.py              Name, version, publisher
│   ├── models.py               Dataclasses: Finding, AnalysisResult, ...
│   ├── limits.py               All safety limits
│   ├── sanitize.py             Neutralizes control/bidi characters in untrusted text
│   ├── jar.py                  Safe archive reading (the only code that touches ZIP data)
│   ├── hashing.py              Streamed SHA-256
│   ├── manifest.py             MANIFEST.MF parser
│   ├── contents.py             Contents inventory, disguised-file detection
│   ├── metadata.py             Fabric/Quilt/Forge/NeoForge/plugin.yml + loader detection
│   ├── classes.py              Java class-file constant-pool parser
│   ├── known_values.py         Reference data: popular mods, domains, sensitive strings
│   ├── indicators.py           Evidence collection + indicator rules
│   ├── hash_database.py        Load/validate/look up/save hashes.json
│   ├── resources.py            Finds bundled files in dev and in the .exe
│   └── pipeline.py             Runs all stages; batch + folder helpers
├── gui/
│   ├── app.py                  Main window
│   ├── widgets.py              Overview, findings table, detail trees
│   ├── worker.py               Background analysis thread
│   └── theme.py                Dark stylesheet
├── reports/exporter.py         JSON and TXT reports
├── database/hashes.json        Local hash database (ships empty)
├── assets/icon.ico, icon.png   Application icon (generated by tools/make_icon.py)
├── tools/
│   ├── add_hash.py             Manage the hash database
│   └── make_icon.py            Regenerate the icon
├── packaging/
│   ├── Minecraft-JAR-Analyzer.spec   PyInstaller configuration
│   └── version_info.txt              Windows file properties
└── tests/                      pytest suite (fixtures are generated, never executed)
```

**Why `packaging/` instead of `build/`?** PyInstaller uses `build/` as its
scratch folder and its `--clean` option wipes it. Keeping the spec in
`packaging/` means it can never be deleted or confused with generated files.

### How one file is analyzed (`pipeline.py`)

1. File info and the real file type (from the first bytes)
2. SHA-256 (streamed in 1 MB chunks) → hash database lookup
3. Open the archive safely: size, entry count and structure are checked *before* parsing
4. Manifest → mod metadata → contents inventory → disguised-file check
5. Parse every class's constant pool. Each class is examined once and then discarded.
6. Detect the loader → run the indicator rules
7. Repeat steps 4–6 for bundled JARs, sharing the same decompression budget
8. Across a batch: check for duplicate mod IDs

Each step is isolated. If one fails, the error is recorded and the rest still run.

### Adding a new indicator rule

1. If it needs new reference data, add it to `analyzer/known_values.py`.
2. If it needs per-class evidence, record it in `ClassEvidence.add()` in `indicators.py`.
3. Write a `rule_something(ctx) -> list[Finding]` function and add it to `RULES`.
4. Add tests to `tests/test_indicators.py`, including one showing it does **not**
   fire on legitimate code.

---

## License

MIT. See [LICENSE](LICENSE).
