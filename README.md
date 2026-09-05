# Phishing Website Detection

A Streamlit application that classifies a URL as legitimate or phishing with the existing trained Random Forest model.

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



