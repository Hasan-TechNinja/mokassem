from django.urls import path, include
from . import views
from rest_framework.routers import DefaultRouter


router = DefaultRouter()
router.register(r'user-subscriptions', views.UserSubscriptionViewSet, basename='user-subscription')

urlpatterns = [
    #Authentication paths
    path('register/', views.RegisterView.as_view(), name='register'),
    path('verify-email/', views.VerifyEmailView.as_view(), name='verify_email'),
    path('login/', views.EmailLoginView.as_view(), name='login'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('password-reset/request/', views.PasswordResetRequestView.as_view(), name='password_reset_request'),
    path('password-reset/confirm/', views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),

    #Profile paths
    path('profile/', views.ProfileView.as_view(), name='profile'),

    # Webhook endpoint for Stripe
    path('webhooks/stripe/', views.StripeWebhookView.as_view(), name='stripe-webhook'),
    
    # Subscription plans
    path('subscription-plans/', views.SubscriptionPlanView.as_view(), name='subscription-plans'),
    
    # Subscription-related endpoints
    path('subscription/', include(router.urls)),
    
    # Payment success and cancellation
    path('payments/success/<int:subscription_id>/', views.SuccessView.as_view(), name='suggestion-categories'),
    # path('payments/cancel/', views.CancelPaymentView.as_view(), name='cancel_payment'),

    path('about/', views.AboutView.as_view(), name='about'),
    path('search/', views.SearchHistoryView.as_view(), name='search')
]
