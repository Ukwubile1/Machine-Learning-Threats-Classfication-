import json
import numpy as np
import joblib
from django.http import JsonResponse
from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import LabelEncoder
import pandas as pd
from django.views.decorators.csrf import csrf_exempt
from .models import PredictionResult
from django.utils import timezone
from django.db.models import Count
from django.shortcuts import render

model = joblib.load("/workspaces/Machine-Learning-Threats-Classfication-/xgboost.pkl")
scaler = StandardScaler()
label_encoder = LabelEncoder()

categorical_columns = [
    'Timestamp', 'SourceIP', 'DestinationIP', 'DnsQuery', 'DnsAnswer', 'DnsAnswerTTL',
    'DnsQueryNames', 'DnsQueryClass', 'DnsQueryType', 'SensorId', 'processName', 'hostName',
    'eventName', 'args', 'stackAddresses'
]

numerical_columns = [
    'NumberOfAnswers', 'DnsResponseCode', 'DnsOpCode', 'sus', 'evil', 'timestamp', 
    'processId', 'parentProcessId', 'userId', 'eventId', 'argsNum', 'returnValue', 
    'threadId', 'mountNamespace'
]

def auto_classify_columns(data):
    categorical_columns = []
    numerical_columns = []

    for col in data.columns:
        if isinstance(data[col].iloc[0], list):
            data[col] = data[col].apply(lambda x: ' '.join(map(str, x)) if isinstance(x, list) else str(x))
            unique_vals = data[col].nunique()
        else:
            unique_vals = data[col].nunique()

        if data[col].dtype == 'object':
            if unique_vals < 0.1 * len(data):
                categorical_columns.append(col)
            else:
                try:
                    # Try to convert to numerical values
                    data[col] = pd.to_numeric(data[col], errors='raise')
                    numerical_columns.append(col)
                except:
                    categorical_columns.append(col)
        else:
            numerical_columns.append(col)

    return categorical_columns, numerical_columns


@csrf_exempt
def predict_threat(request):
    data = json.loads(request.body)

    input_data = {
        'Timestamp': data.get('timestamp', 0),
        'SourceIP': data.get('SourceIP', ''),
        'DestinationIP': data.get('DestinationIP', ''),
        'DnsQuery': data.get('DnsQuery', ''),
        'DnsAnswer': data.get('DnsAnswer', ''),
        'DnsAnswerTTL': data.get('DnsAnswerTTL', 0),
        'DnsQueryNames': data.get('DnsQueryNames', ''),
        'DnsQueryClass': data.get('DnsQueryClass', ''),
        'DnsQueryType': data.get('DnsQueryType', ''),
        'SensorId': data.get('SensorId', ''),
        'processName': data.get('processName', ''),
        'hostName': data.get('hostName', ''),
        'eventName': data.get('eventName', ''),
        'args': data.get('args', ''),
        'stackAddresses': data.get('stackAddresses', ''),
        'NumberOfAnswers': data.get('NumberOfAnswers', 0),
        'DnsResponseCode': data.get('DnsResponseCode', 0),
        'DnsOpCode': data.get('DnsOpCode', 0),
        'sus': data.get('sus', 0),
        'evil': data.get('evil', 0),
        'timestamp': data.get('timestamp', 0),
        'processId': data.get('processId', 0),
        'parentProcessId': data.get('parentProcessId', 0),
        'userId': data.get('userId', 0),
        'eventId': data.get('eventId', 0),
        'argsNum': data.get('argsNum', 0),
        'returnValue': data.get('returnValue', 0),
        'threadId': data.get('threadId', 0),
        'mountNamespace': data.get('mountNamespace', 0),
    }

    input_df = pd.DataFrame([input_data])
    categorical_columns, numerical_columns = auto_classify_columns(input_df)
    input_df[numerical_columns] = scaler.fit_transform(input_df[numerical_columns])

    expected_columns = categorical_columns + numerical_columns
    df_input = input_df[expected_columns]

    for col in expected_columns:
        if col not in df_input.columns:
            df_input[col] = 0 

    for col in categorical_columns:
        df_input[col] = label_encoder.fit_transform(input_df[col])
    
    columns_to_remove = ['args', 'eventName', 'hostName', 'processName', 'stackAddresses']
    df_input = df_input.drop(columns=columns_to_remove, errors='ignore')
    prediction = model.predict(df_input)
    prediction_record = PredictionResult(
        timestamp=input_data['timestamp'],
        processId=input_data['processId'],
        threadId=input_data['threadId'],
        parentProcessId=input_data['parentProcessId'],
        userId=input_data['userId'],
        mountNamespace=input_data['mountNamespace'],
        processName=input_data['processName'],
        hostName=input_data['hostName'],
        eventId=input_data['eventId'],
        eventName=input_data['eventName'],
        stackAddresses=input_data['stackAddresses'],
        argsNum=input_data['argsNum'],
        returnValue=input_data['returnValue'],
        args=input_data['args'],
        sus=input_data['sus'],
        evil=input_data['evil'],
        prediction=int(prediction[0]),
        prediction_timestamp=timezone.now()
    )
    prediction_record.save()
    return JsonResponse({"prediction": int(prediction[0])})


def dashboard(request):
    total_events = PredictionResult.objects.count()
    total_suspicious_events = PredictionResult.objects.filter(evil=1).count()
    devices_protected = 13

    last_10_predictions = PredictionResult.objects.all().order_by('-prediction_timestamp')[:10]

    event_counts_by_name = PredictionResult.objects.values('eventName').annotate(event_count=Count('eventName')).order_by('-event_count')
    event_counts_by_time = PredictionResult.objects.values('prediction_timestamp__date').annotate(event_count=Count('prediction_timestamp__date')).order_by('prediction_timestamp__date')
    detections_by_time = PredictionResult.objects.filter(evil=1).values('prediction_timestamp__date').annotate(detection_count=Count('evil')).order_by('prediction_timestamp__date')

    event_dates = [entry['prediction_timestamp__date'].strftime('%B %d, %Y') for entry in event_counts_by_time]
    event_counts = [entry['event_count'] for entry in event_counts_by_time]
    detection_dates = [entry['prediction_timestamp__date'].strftime('%B %d, %Y') for entry in detections_by_time]
    detection_counts = [entry['detection_count'] for entry in detections_by_time]

    event_names = [entry['eventName'] for entry in event_counts_by_name]
    event_name_counts = [entry['event_count'] for entry in event_counts_by_name]

    context = {
        'total_events': total_events,
        'total_suspicious_events': total_suspicious_events,
        'devices_protected': devices_protected,
        'event_dates': event_dates,
        'event_counts': event_counts,
        'detection_dates': detection_dates,
        'detection_counts': detection_counts,
        'event_names': event_names,
        'event_name_counts': event_name_counts,
        "last_10_predictions": last_10_predictions,
    }
    return render(request, 'dashboard.html', context)
