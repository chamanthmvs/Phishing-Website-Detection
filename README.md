# Phishing Website Detection

Phishing Website Detection is a machine learning project that classifies URLs as legitimate or potentially phishing. It provides a Streamlit interface where a user can enter a URL, run the trained Random Forest model, and view both the prediction and the URL signals used for that prediction.

For the visual project presentation, visit the [Phishing Website Detection project page](https://chamanthmvs.github.io/Phishing-Website-Detection/).

## Why this project matters

Financial services and other online platforms process a large volume of real-time transactions. This makes them attractive targets for fraud and social engineering attacks. Phishing is one of the most common techniques used to steal sensitive information from unsuspecting users.

In a typical phishing attack, an attacker creates a website that imitates a trusted organization. The victim may be directed to the site through an email, message, or misleading link and asked to enter information such as a name, telephone number, account details, or password. The stolen information can then be used for unauthorized access or fraudulent transactions.

Phishing websites often look convincing and attackers continuously change their techniques to avoid detection. An automated URL analysis system can help identify suspicious characteristics before a user trusts a link.

## Project objective

This project explores how URL-based features can be used to distinguish legitimate websites from phishing websites. The feature-extraction workflow analyzes signals such as:

- URL length and redirection patterns
- IP addresses and prefix/suffix separation
- Number of subdomains
- URL-shortening services
- HTTPS token usage
- DNS and domain-registration information
- Domain age and statistical reputation signals

These features are passed to a trained Random Forest classifier. The application then displays the resulting classification as **Legitimate** or **Phishing**.

## Application workflow

1. Enter a complete URL in the Streamlit interface.
2. Extract the URL features used during model training.
3. Pass the numeric feature vector to the saved Random Forest model.
4. Display the prediction and the extracted feature values.

This tool is intended for experimentation and educational use. Its prediction should not be treated as a guarantee that a website is safe or malicious.

## Repository contents

- `app.py` - Streamlit application and prediction workflow
- `featureExtraction.py` - URL feature-extraction logic
- `RandomForestModel.sav` - trained Random Forest model
- `notebooks/` - feature extraction and model-training notebooks
- `raw_datasets/` - source URL datasets used for experimentation
- `docs/` - standalone GitHub Pages project presentation
- `requirements.txt` - Python dependencies

## Run locally

Create or activate the repository virtual environment, then install the dependencies into that environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Start the application:

```bash
streamlit run app.py
```

The app extracts the same URL signals used by the model, displays the prediction, and lets you inspect the extracted values.

## Reproduce model training

The `raw_datasets/` directory contains the source URL lists, and `notebooks/` documents feature extraction and model training. Run the feature-extraction notebook first; it creates the ignored `generated_data/` CSV files consumed by the classifier notebooks.

The production runtime consists of `app.py`, `featureExtraction.py`, and `RandomForestModel.sav`. The notebooks and raw datasets are kept separately for reproducibility and experimentation.

## Built by

Built by **chamanthmvs**.



