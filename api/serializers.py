from rest_framework import serializers
from authentication.models import EmailVerification, PasswordResetCode, Profile
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.models import User
import random
import string
from django.core.mail import send_mail



class RegistrationSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all(), message="This email is already in use.")]
    )
    password = serializers.CharField(
        write_only=True,
        min_length=8,
        style={'input_type': 'password'},
        validators=[validate_password]
    )
    confirm_password = serializers.CharField(
        write_only=True,
        min_length=8,
        style={'input_type': 'password'}
    )

    class Meta:
        model = User
        fields = ('email', 'password', 'confirm_password')

    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match.")
        return data

    def generate_username(self, base):
        username = base
        while User.objects.filter(username=username).exists():
            suffix = ''.join(random.choices(string.digits, k=4))
            username = f"{base}_{suffix}"
        return username

    def create(self, validated_data):
        validated_data.pop('confirm_password')

        email = validated_data['email']
        base_username = email.split('@')[0]
        generated_username = self.generate_username(base_username)

        user = User.objects.create_user(
            username=generated_username,
            email=email,
            password=validated_data['password'],
            is_active=False
        )

        code = str(random.randint(1000, 9999))
        EmailVerification.objects.create(user=user, code=code)

        send_mail(
            'Your Verification Code',
            f'Your verification code is {code}',
            'noreply@example.com',
            [email],
            fail_silently=False
        )

        return user