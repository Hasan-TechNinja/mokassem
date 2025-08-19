from django.shortcuts import render
from authentication.models import EmailVerification, PasswordResetCode
from .serializers import RegistrationSerializer
from django.contrib.auth.models import User
import random
from django.core.mail import send_mail
from django.contrib.auth import authenticate, login

from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import permissions, status
from rest_framework_simplejwt.tokens import RefreshToken

# Create your views here.


class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email = request.data.get('email')
        
        existing_user = User.objects.filter(email=email).first()

        if existing_user:
            if not existing_user.is_active:
                EmailVerification.objects.filter(user=existing_user).delete()
                code = str(random.randint(100000, 999999))
                EmailVerification.objects.create(user = existing_user, code=code)

                send_mail(
                    subject='Your New Verificaiton code',
                    message=(
                        f"Hello {email},\n\n"
                        "Thank you for registering with us.\n"
                        f"Your verification code is: {code}\n\n"
                        "Please use this code to verify your account.\n"
                        "If you did not request this, please ignore this email.\n\n"
                        "Best regards,\n"
                        "The 1 Step Coach Live Team"
                    ),
                    from_email= 'noreply@gmail.com',
                    recipient_list=[email],
                    fail_silently=False
                )
                return Response({"message": "A new verification code has been sent to your email."}, status=status.HTTP_200_OK)
            return Response({"error": "This email is already in use by an active account."}, status=status.HTTP_400_BAD_REQUEST)

        serializer = RegistrationSerializer(data = request.data)
        if serializer.is_valid():
            user = serializer.save()
            refresh = RefreshToken.for_user(user)
            access_token = refresh.access_token

            return Response({'refresh': str(refresh)}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class VerifyEmailView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        code = request.data.get('code')
        email = request.data.get('email')

        if not code:
            return Response({"error":"code is required."}, status=status.HTTP_400_BAD_REQUEST)
        elif not email:
            return Response({"error":"email is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email = email)
            verification = EmailVerification.objects.get(user = user)

            if verification.code == code:
                if verification.is_expired():
                    return Response({"error": "Verification code has expired."}, status=status.HTTP_400_BAD_REQUEST)

                user.is_active = True
                user.save()

                verification.delete()
                login(request, user)

                refresh = RefreshToken.for_user(user)
                access_token = refresh.access_token

                return Response({
                    'message': 'Email verified successfully and user logged in.',
                    'access': str(access_token),
                    'refresh': str(refresh)
                }, status=status.HTTP_200_OK)
                
            else:
                return Response({"error": "Invalid verification code."}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({"error": "User with this email dose not exist."}, status= status.HTTP_400_BAD_REQUEST)
        except EmailVerification.DoesNotExist:
            return Response({"error": "No verificaiton record found for this user."}, status=status.HTTP_400_BAD_REQUEST)