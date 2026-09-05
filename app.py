from pathlib import Path
import pickle
import sys

import numpy as np
import streamlit as st
from sklearn.tree import _tree

import featureExtraction


MODEL_PATH = Path(__file__).with_name("RandomForestModel.sav")


@st.cache_resource
def load_model():
    import sklearn.ensemble._forest as forest
    import sklearn.tree._classes as tree

    sys.modules["sklearn.ensemble.forest"] = forest
    sys.modules["sklearn.tree.tree"] = tree

    class CompatibleTree(_tree.Tree):
        def __setstate__(self, state):
            nodes = state.get("nodes") if isinstance(state, dict) else None
            if nodes is not None and "missing_go_to_left" not in nodes.dtype.names:
                converted = np.zeros(nodes.shape, dtype=_tree.NODE_DTYPE)
                for name in nodes.dtype.names:
                    converted[name] = nodes[name]
                state = dict(state)
                state["nodes"] = converted
            return super().__setstate__(state)

    class CompatibleUnpickler(pickle.Unpickler):
        def find_class(self, module, name):
            if module == "sklearn.tree._tree" and name == "Tree":
                return CompatibleTree
            return super().find_class(module, name)

    with MODEL_PATH.open("rb") as model_file:
        model = CompatibleUnpickler(model_file).load()

    if not hasattr(model, "estimator") and hasattr(model, "base_estimator"):
        model.estimator = model.base_estimator
    return model


def predict_url(url):
    features = featureExtraction.getAttributess(url)
    prediction = int(load_model().predict(features.to_numpy())[0])
    return prediction, features


st.set_page_config(
    page_title="PhishGuard | URL Scanner",
    page_icon="🛡️",
    layout="centered",
)

st.markdown(
    """
    <style>
    :root {
        --ink: #17202a;
        --muted: #5f6b76;
        --accent: #0c6e69;
        --surface: #ffffff;
        --background: #f4f7f5;
    }
    .stApp {
        background: radial-gradient(circle at 100% 0%, #d8eee7 0, transparent 30%),
                    var(--background);
        color: var(--ink);
    }
    .hero {
        padding: 2.6rem 0 1.5rem;
    }
    .eyebrow {
        color: var(--accent);
        font-size: 0.78rem;
        font-weight: 700;
        letter-spacing: 0.12em;
        text-transform: uppercase;
    }
    .hero h1 {
        color: var(--ink);
        font-size: clamp(2.2rem, 7vw, 4.4rem);
        line-height: 0.98;
        margin: 0.4rem 0 0.8rem;
    }
    .hero p {
        color: var(--muted);
        font-size: 1.05rem;
        max-width: 38rem;
    }
    .result {
        border-left: 5px solid var(--accent);
        background: var(--surface);
        border-radius: 0.75rem;
        box-shadow: 0 14px 36px rgba(23, 32, 42, 0.09);
        margin: 1.5rem 0;
        padding: 1.25rem 1.4rem;
    }
    .result.phishing {
        border-left-color: #c74634;
    }
    .result-label {
        color: var(--muted);
        font-size: 0.8rem;
        font-weight: 700;
        letter-spacing: 0.08em;
        text-transform: uppercase;
    }
    .result-value {
        color: var(--ink);
        font-size: 2rem;
        font-weight: 750;
        margin-top: 0.2rem;
    }
    .footer-credit {
        border-top: 1px solid #dce6e1;
        color: var(--muted);
        font-size: 0.82rem;
        margin-top: 3rem;
        padding: 1rem 0 0.5rem;
        text-align: center;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="hero">
        <div class="eyebrow">PhishGuard / URL intelligence</div>
        <h1>Check a link before you trust it.</h1>
        <p>Scan a URL with the project's trained Random Forest model and inspect the signals used for the prediction.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

with st.form("url_scan_form"):
    url = st.text_input(
        "Website URL",
        placeholder="https://example.com/account",
        help="Enter the complete URL, including http:// or https:// when available.",
    ).strip()
    submitted = st.form_submit_button("Scan URL", type="primary", width="stretch")

if submitted:
    if not url:
        st.warning("Enter a URL to start the scan.")
    else:
        try:
            with st.spinner("Extracting URL signals and running the model..."):
                prediction, features = predict_url(url)

            label = "Phishing" if prediction else "Legitimate"
            result_class = "phishing" if prediction else ""
            st.markdown(
                f"""
                <div class="result {result_class}">
                    <div class="result-label">Scan result</div>
                    <div class="result-value">{label}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            st.caption(f"Scanned URL: {url}")
            with st.expander("View extracted signals"):
                st.dataframe(features.T.rename(columns={0: "Value"}), width="stretch")
        except Exception as error:
            st.error(f"The URL could not be scanned: {error}")

st.markdown('<div class="footer-credit">Built by chamanthmvs</div>', unsafe_allow_html=True)
