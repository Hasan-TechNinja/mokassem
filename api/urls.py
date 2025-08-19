from django.urls import path
from . import views

urlpatterns = [
    #Authentication paths
    path('register/', views.RegisterView.as_view(), name='register'),
    path('verify-email/', views.VerifyEmailView.as_view(), name='verify_email'),
    path('login/', views.EmailLoginView.as_view(), name='login'),
]
