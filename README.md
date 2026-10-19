# AI Red Teamer

A tool that tests an AI chatbot with malicious prompts and generates a security findings report. It has a command-line scanner and a web dashboard.

## What it tests
- **Prompt injection**: direct override, fake delimiters, indirect (document) injection, encoded injection
- **Jailbreaks**: DAN persona, roleplay, fake developer mode, fake authority
- **Sensitive-data leakage**: system prompt extraction, secrets/API keys, personal data
- **Unsafe responses**: phishing, malware, harassment, account hacking

Each test is marked PASS, FAIL (vulnerable) or REVIEW (check manually). The report includes an overall risk score, each finding with its evidence, and a recommended fix.

## Project structure
- `red_teamer.py`: scanner and report generator (command line, no dependencies)
- `app.py`: web backend (Flask) that uses the scanner
- `templates/index.html`: web frontend (dashboard)
- `requirements.txt`: Python packages for the web app

## Requirements
Python 3.8 or higher. The command-line tool needs no extra packages. The web app needs Flask.

## Option 1: Web dashboard

    pip install -r requirements.txt
    python app.py

Open http://127.0.0.1:5000 in your browser, choose the chatbot, and click **Run security tests**. You can download the report as Markdown or JSON.

## Option 2: Command line

Demo (built-in test chatbot):

    python red_teamer.py --target mock

Your own chatbot API (JSON in, JSON out):

    python red_teamer.py --target http --url http://localhost:8000/chat --request-key message --response-key reply --canary "SECRET-123"

OpenAI-compatible API (set the key in the API_KEY environment variable):

    python red_teamer.py --target openai --url https://api.openai.com/v1/chat/completions --model gpt-4o-mini

Run only some categories:

    python red_teamer.py --target mock --only prompt_injection jailbreak

Reports are saved in the `reports/` folder.

## Limitations
Detection is rule-based, so it can give false positives and negatives. Confirm findings manually.

## Disclaimer
Only test chatbots you own or have written permission to test. The web app runs on your own computer (127.0.0.1) only; do not expose it to the internet.
