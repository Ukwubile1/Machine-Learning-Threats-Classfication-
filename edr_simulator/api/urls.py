from django.urls import path
from .views import predict_threat, dashboard

urlpatterns = [
    path('predict/', predict_threat, name='predict_threat'),
    path('', dashboard, name='dashboard'),
]
