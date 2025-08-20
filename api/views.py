from django.shortcuts import render, redirect
from authentication.models import EmailVerification, PasswordResetCode, Profile
from .serializers import PasswordResetConfirmSerializer, RegistrationSerializer, ProfileSerializer
from django.contrib.auth.models import User
import random
from django.core.mail import send_mail
from django.contrib.auth import authenticate, login
from api.serializers import EmailTokenObtainPairSerializer
from django.contrib.auth.hashers import make_password

from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import permissions, status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken

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


class EmailLoginView(TokenObtainPairView):
    serializer_class = EmailTokenObtainPairSerializer


class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        
        refresh_token = request.data.get("refresh")

        if not refresh_token:
            return Response({"detail": "Refresh token is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:

            token = RefreshToken(refresh_token)

            token.blacklist()

            return Response({"detail": "Logout successful."}, status=status.HTTP_205_RESET_CONTENT)

        except InvalidToken:
            return Response({"detail": "The token is invalid or expired."}, status=status.HTTP_400_BAD_REQUEST)
        except TokenError as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"detail": f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


class PasswordResetRequestView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({"error": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = User.objects.get(email = email)
            if user.is_active == False:
                return redirect("")
            
            PasswordResetCode.objects.filter(user = user).delete()

            code = str(random.randint(100000, 999999))
            PasswordResetCode.objects.create(user = user, code = code)

            if user.first_name:
                name = user.first_name
            elif user.email:
                name = user.email
            else:
                name = user.username

            send_mail(
                subject="Password reset Request",
                message=(
                    f"Hello, {name}\n"
                        "We received a request to reset your account password.\n"
                        f"Your password reset code is: "
                        f"{code}\n\n"
                        "If you did not request this, please ignore this email.\n"
                        "For security, this code will expire in 3 minutes.\n\n"
                        "Best regards,\n"
                        "The 1 Step Coach Live Team"
                ),
                from_email='noreply@example.com',
                recipient_list=[email],
                fail_silently=False
            )
            return Response({"message": "A password reset code has been sent to your email."}, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({"error": "User with this email does not exist."}, status=status.HTTP_404_NOT_FOUND)
        


class PasswordResetConfirmView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)

        if serializer.is_valid():
            email = serializer.validated_data['email']
            code = serializer.validated_data['code']
            new_password = serializer.validated_data['new_password']

            try:
                user = User.objects.get(email=email)

                password_reset = PasswordResetCode.objects.filter(user=user, code=code).first()

                if not password_reset:
                    return Response({"error": "Invalid or expired reset code."}, status=status.HTTP_400_BAD_REQUEST)

                user.password = make_password(new_password)
                user.save()

                password_reset.delete()

                return Response({'detail': 'Password has been reset.'}, status=status.HTTP_200_OK)

            except User.DoesNotExist:
                return Response({"error": "User with this email does not exist."}, status=status.HTTP_404_NOT_FOUND)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class ProfileView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):

        user = request.user
        profile, created = Profile.objects.get_or_create(user=user)
        profile_data = ProfileSerializer(profile).data
        return Response(profile_data, status=status.HTTP_200_OK)

    def put(self, request):

        user = request.user
        profile, created = Profile.objects.get_or_create(user=user)

        serializer = ProfileSerializer(profile, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


