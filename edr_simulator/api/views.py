import json
import numpy as np
import joblib
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import ThreatDetectionLog

# Load the trained XGBoost model
model = joblib.load("xdr_model.pkl")  # Ensure this file exists

@csrf_exempt
def predict_threat(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            features = np.array(data["features"]).reshape(1, -1)
            
            # Get prediction and probability
            prob = model.predict_proba(features)[0, 1]  # Probability of "Threat"
            prediction = bool(model.predict(features)[0])  # Convert to Boolean

            # Save to database
            log_entry = ThreatDetectionLog.objects.create(
                features=data["features"],
                prediction=prediction,
                probability=prob
            )
            
            return JsonResponse({
                "threat_detected": prediction,
                "probability": round(prob, 4),
                "log_id": log_entry.id
            })
        
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    
    return JsonResponse({"message": "Send a POST request with features"}, status=400)
