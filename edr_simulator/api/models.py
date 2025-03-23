from django.db import models

class ThreatDetectionLog(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    features = models.JSONField()
    prediction = models.BooleanField()
    probability = models.FloatField()

    def __str__(self):
        return f"Detection at {self.timestamp} - Threat: {self.prediction}"
