from fastapi import FastAPI
from pydantic import BaseModel
import pickle
import FeatureExtraction

# Load the model (make sure you have the correct path to the model file)
RFmodel = pickle.load(open('RandomForestModel.sav', 'rb'))

app = FastAPI()

# Define request body model
class URLRequest(BaseModel):
    url: str

# API endpoint for URL prediction
@app.post("/predict")
async def predict(request: URLRequest):
    url = request.url
    print(f"Received URL: {url}")
    
    # Feature extraction
    data = FeatureExtraction.getAttributess(url)
    
    # Prediction
    predicted_value = RFmodel.predict(data)
    
    # return response
    if predicted_value == 0:
        return {"prediction": "Legitimate"}
    else:
        return {"prediction": "Phishing"}
