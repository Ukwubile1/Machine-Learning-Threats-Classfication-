from django.db import models

class PredictionResult(models.Model):
    timestamp = models.FloatField()
    processId = models.IntegerField()
    threadId = models.IntegerField()
    parentProcessId = models.IntegerField()
    userId = models.IntegerField()
    mountNamespace = models.IntegerField()
    processName = models.CharField(max_length=255)
    hostName = models.CharField(max_length=255)
    eventId = models.IntegerField()
    eventName = models.CharField(max_length=255)
    stackAddresses = models.JSONField()  # Use JSONField for list of ints
    argsNum = models.IntegerField()
    returnValue = models.IntegerField()
    args = models.JSONField()  # JSONField for list of dictionaries
    sus = models.IntegerField()
    evil = models.IntegerField()
    
    prediction = models.IntegerField()  # The predicted class (0 or 1)
    prediction_timestamp = models.DateTimeField(auto_now_add=True)  # Timestamp for when prediction was made

    def __str__(self):
        return f"PredictionResult {self.id} - {self.processName} - {self.prediction}"
