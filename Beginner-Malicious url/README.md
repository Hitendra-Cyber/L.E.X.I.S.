# Malicious URL Analytics & Detection Dashboard

## Introduction

This is a visual dashboard that helps people check whether a web link looks safe or suspicious.
It is built to make URL risk analysis easier to understand, even if you are not a security expert.

## What It Does

- Generates a balanced synthetic dataset of safe and malicious URLs.
- Engineers structural, character-density, entropy, routing, and threat-keyword features.
- Trains a Random Forest classifier with stratified evaluation.
- Provides a live URL analyzer in the Streamlit sidebar.
- Renders Plotly dashboards for executive-level exploration.

## How It Does It

The app studies the shape and text of a URL instead of visiting the website.

It looks at things like:

- how long the link is,
- how many dots, dashes, question marks, and other special characters it has,
- whether it contains suspicious words like `login`, `verify`, or `bank`,
- whether the link is using a raw IP address,
- how many subdomains it has,
- how unusual the text pattern looks overall.

After that, the model compares those features against examples of safe and malicious links and gives a result.

## How A New User Can Use It

### 1. Start the app

Open a terminal in this folder and run:

```powershell
streamlit run app.py
```

Then open the local address shown in the terminal, usually `http://localhost:8501`.

### 2. Paste a URL

In the sidebar, type or paste a web link into the URL box.

Examples:

- `https://example.com/login?session=123`
- `https://secure.bankname.com/account/verify`
- `http://192.168.1.10/login`

### 3. Read the result

The app will quickly show whether the link looks:

- `Safe` with a success message,
- `Malicious` with an error message.

### 4. Explore the dashboard

Use the charts, summary cards, and table to understand why the app made that decision.

The main panels show:

- a quick health summary of the dataset and model,
- comparison charts for safe vs. malicious links,
- the full engineered dataset,
- grouped statistics for deeper review.

### 5. Use the filters if needed

If you want to focus on a smaller set of examples, use the sidebar filters for class, theme, search terms, and URL length.

## Quick Start Guide

If you just want to use the app, follow these steps:

1. Open a terminal inside this folder.
2. Create and activate a virtual environment.
3. Install the dependencies from `requirements.txt`.
4. Start the app with `streamlit run app.py`.
5. Open the local URL shown in the terminal, usually `http://localhost:8501`.

## What The Verdict Means

- `Safe` means the model did not detect a strong phishing pattern.
- `Malicious` means the model found suspicious lexical signals such as threat keywords, IP-hosted URLs, or unusual structure.

This is a detection demo, not a production security control. Always verify suspicious links with additional security tools and human review.

## How To Use The Dashboard

### 1. Enter a URL in the sidebar

Type or paste any URL into the "Enter a URL for instant analysis" field on the left.

The app will immediately:

- extract lexical features from the URL,
- show the feature snapshot in the sidebar,
- predict whether the URL looks `Safe` or `Malicious`,
- display a green success message for safer URLs,
- display a red error message for suspicious URLs.

### 2. Read the executive KPI cards

At the top of the dashboard, the four cards summarize:

- total dataset size,
- malicious prevalence rate,
- model accuracy,
- model F1-score.

### 3. Inspect the visual analytics

Use the two charts in the middle of the page:

- the URL length histogram/density chart compares safe vs. malicious URL lengths,
- the grouped horizontal bar chart compares special character usage across both classes.

### 4. Explore the dataset table

The large table near the bottom shows the engineered dataset.

Use the sidebar filters to narrow the table by:

- safety class,
- URL theme,
- keyword search,
- URL length range.

### 5. Expand the statistics and model details

Open the right-side expanders to review:

- grouped descriptive statistics by class,
- model diagnostics,
- confusion matrix payload.

## Local Setup

1. Create a virtual environment.
2. Install dependencies from `requirements.txt`.
3. Run `streamlit run app.py`.

### Windows PowerShell Example

```powershell
& "C:/Program Files/Python313/python.exe" -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
streamlit run app.py
```

### First Run Notes

- The first launch may take a few seconds while Streamlit starts.
- If Windows blocks script execution, run PowerShell as needed with the correct execution policy for your environment.
- Use the local address printed in the terminal to open the dashboard in your browser.

## Security Notes

- Do not commit `.streamlit/secrets.toml`, `.env`, API keys, or tokens.
- Keep the virtual environment and caches untracked.
- Review any future data files before publishing them.
- Use `.env.example` as the template if you need environment variables later.

## Repository Ready For GitHub

This repository now includes the basic files you usually want before publishing:

- `.gitignore` for local Python and Streamlit clutter,
- `LICENSE` for clear reuse terms,
- `SECURITY.md` for responsible vulnerability reporting,
- `.github/workflows/ci.yml` for a basic code health check,
- `.env.example` for future environment variables without exposing secrets.

## Using The Dashboard Safely

- This project ships with synthetic URLs, so the dataset is safe to publish.
- Do not paste private or internal company URLs unless you are allowed to analyze them.
- If you later add real datasets, scrub or anonymize them before committing.

## Project Files

- `app.py` contains the full dashboard, feature engineering, and model pipeline.
- `requirements.txt` pins the Python dependencies.
- `.streamlit/config.toml` sets the dark theme used by the dashboard.
