# AI Network Port Scanner

A desktop port scanner built with Python and Tkinter. It scans TCP ports on a target host, lists open ports with common service names, and includes an **AI assistant** to help interpret results, note typical risks, and suggest basic hardening ideas.

**Important:** Only scan networks and systems you are authorized to test. Unauthorized scanning may be illegal.

![License](https://img.shields.io/badge/License-MIT-blue)
![PRS](https://img.shields.io/badge/PRs-Welcome!-brightgreen.svg)

## Features

- **Port scan:** configurable port range, threaded worker pool, progress and elapsed time
- **Results:** table view with export to TXT or CSV
- **AI assistant:** explains scan output in plain language (requires a Gemini API key in `.env`)
- **Scope guard:** off-topic questions receive a fixed response (see app behavior)

## Requirements

- **Python 3.10+** (tested with 3.11)
- **Tkinter** (usually bundled with Python on Windows; on Linux install `python3-tk`)

## Setup

1. Clone or copy this project folder.

2. Create a virtual environment (recommended):

   ```bash
   python -m venv .venv
   .venv\Scripts\activate
   ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Configure API key for the AI assistant:

   - Copy `GEMINI_API_KEY` into the project `.env` file (same folder as `main.py`):

   ```
   GEMINI_API_KEY=your_key_here
   ```

## How To Run?

From the project root:

```bash
python main.py
```

## Project layout

| Path | Purpose |
|------|---------|
| `main.py` | Application entry point |
| `src/scanner.py` | Port scanning logic |
| `src/ui.py` | Tkinter GUI |
| `src/ai_assistant.py` | Gemini client and prompt guard |
| `.env` | Local secrets (API key) |

## Dependencies

Only these packages are required for this app (see `requirements.txt`):

- `google-genai` — Gemini API client
- `python-dotenv` — load `.env` from the project directory

## Troubleshooting

- **AI shows “Not connected”:** Ensure `.env` sits next to `main.py` and contains `GEMINI_API_KEY=...`. Restart the app after editing `.env`.
- **Import errors:** Run `pip install -r requirements.txt` inside the same environment you use to run `python main.py`.

## Contributing

Contributions make open source great — all skill levels are welcome, whether it's fixing a typo, adding a new model, or building out a major feature.

### How to Contribute

**1. Fork the repository**

Click the **Fork** button at the top of this page.

**2. Create a feature branch**

```bash
git checkout -b feature/your-feature-name

# or for bug fixes:

git checkout -b fix/your-bug-description
```

**3. Make your changes**

Keep commits focused and write clear commit messages. If you're adding a new model, please include the encoding name and a link to the provider's tokenization documentation.

**4. Open a Pull Request**

Push your branch and open a PR against `main`. Describe what you changed and why.

### Contributing Guidelines

- Follow PEP 8 code style
- Add tests for new features
- Update documentation
- Use meaningful commit messages

## Contact

Built and maintained by **[Mohit Pandey :)](https://github.com/mohitpandeycs)**

-  GitHub — [@mohitpandeycs](https://github.com/mohitpandeycs)
-  LinkedIn — [in/mohitpandeycs](https://linkedin.com/in/mohitpandeycs)
-  Twitter / X — [@mohitpandeycs](https://x.com/mohitpandeycs)

Found a bug? [Open an issue](https://github.com/mohitpandeycs/Token-Visualizer/issues). Have a feature idea? [Start a discussion](https://github.com/mohitpandeycs/Token-Visualizer/discussions).


## License

This project is released under the [MIT License](https://opensource.org/licenses/MIT).

 > If you find this repo useful, consider giving this repo a ⭐ Star, it helps other developers to discover the project.

