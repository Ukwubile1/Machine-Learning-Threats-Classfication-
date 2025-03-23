import os
import json
import joblib
import numpy as np
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render
from django.conf import settings

# Load the pre-trained XGBoost
MODEL_PATH = os.path.join(settings.BASE_DIR, 'xgboost.pkl')
model = joblib.load(MODEL_PATH)

@csrf_exempt  # Disable CSRF for simplicity
def predict_threat(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            features = np.array(data['features']).reshape(1, -1)  # Ensure correct shape
            prediction = model.predict(features)[0]
            response = {'threat_detected': bool(prediction)}
            return JsonResponse(response, status=200)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    return JsonResponse({'message': 'Send a POST request with features.'}, status=405)
