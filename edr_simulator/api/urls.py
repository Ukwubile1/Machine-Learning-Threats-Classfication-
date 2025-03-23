from django.urls import path
from .views import predict_threat

urlpatterns = [
    path('predict/', predict_threat, name='predict_threat'),
]
