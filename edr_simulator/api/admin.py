from django.contrib import admin
from .models import ThreatDetectionLog

@admin.register(ThreatDetectionLog)
class ThreatDetectionLogAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'prediction', 'probability')
    ordering = ('-timestamp',)
