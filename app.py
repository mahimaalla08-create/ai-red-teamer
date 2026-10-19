#!/usr/bin/env python3
"""
AI Red Teamer - web app (backend)
Run:  python app.py   then open http://127.0.0.1:5000
It reuses the scanner in red_teamer.py.
Runs on 127.0.0.1 only; do not expose it to the internet.
"""
import os
import tempfile
from datetime import datetime

from flask import Flask, Response, jsonify, render_template, request

import red_teamer as rt

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def scan():
    d = request.get_json(force=True, silent=True) or {}
    mode = d.get("target", "mock")
    canaries = [c.strip() for c in d.get("canaries", []) if c and c.strip()]

    if mode == "mock":
        target, name = rt.MockTarget(), "Built-in demo chatbot (mock)"
        canaries.append(rt.DEMO_CANARY)
    elif mode == "http":
        url = (d.get("url") or "").strip()
        if not url:
            return jsonify(error="Please enter the chatbot URL."), 400
        headers = {}
        for line in (d.get("headers") or "").splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
        target = rt.HTTPTarget(url, (d.get("request_key") or "message").strip(),
                               (d.get("response_key") or "response").strip(), headers)
        name = url
    elif mode == "openai":
        url = (d.get("url") or "").strip()
        key = (d.get("api_key") or os.environ.get("API_KEY", "")).strip()
        if not url or not key:
            return jsonify(error="URL and API key are required for this mode."), 400
        model = (d.get("model") or "gpt-4o-mini").strip()
        target = rt.OpenAITarget(url, model, key, (d.get("system_prompt") or None))
        name = f"{url} ({model})"
    else:
        return jsonify(error="Unknown target type."), 400

    cats = d.get("categories") or None
    attacks = [a for a in rt.ATTACKS if not cats or a.category in cats]
    if not attacks:
        return jsonify(error="Select at least one test category."), 400

    results = rt.run(target, attacks, canaries)
    summary = rt.summarize(results)
    meta = {"target": name, "date": datetime.now().strftime("%Y-%m-%d %H:%M")}
    return jsonify(meta=meta, summary=summary, results=results)


@app.route("/api/report", methods=["POST"])
def report():
    """Turn scan results into a downloadable Markdown report."""
    d = request.get_json(force=True, silent=True) or {}
    with tempfile.NamedTemporaryFile("r", suffix=".md", delete=False, encoding="utf-8") as tmp:
        path = tmp.name
    try:
        rt.write_markdown(path, d["results"], d["summary"], d["meta"])
        with open(path, encoding="utf-8") as f:
            md = f.read()
    finally:
        os.remove(path)
    return Response(md, mimetype="text/markdown",
                    headers={"Content-Disposition": "attachment; filename=redteam_report.md"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
