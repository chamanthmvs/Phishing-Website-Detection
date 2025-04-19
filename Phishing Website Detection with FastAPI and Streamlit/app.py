import streamlit as st
import requests

# FastAPI endpoint URL 
API_URL = "http://127.0.0.1:8000/predict" 

# Streamlit UI
st.title("Phishing URL Detection")
url = st.text_input("Enter URL:")

if st.button("Check URL"):
    if url:
        # Send request to FastAPI
        response = requests.post(API_URL, json={"url": url})
        
        if response.status_code == 200:
            prediction = response.json()['prediction']
            st.write(f"The URL is: **{prediction}**")
        else:
            st.write("Error: Unable to get prediction.")
    else:
        st.write("Please enter a URL.")
