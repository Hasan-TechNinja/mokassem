from rest_framework import serializers
from authentication.models import EmailVerification, PasswordResetCode, Profile
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.models import User
import random
import string
from django.core.mail import send_mail
from rest_framework_simplejwt.tokens import RefreshToken



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
    

class EmailTokenObtainPairSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("Invalid email or password")

        if not user.check_password(password):
            raise serializers.ValidationError("Invalid email or password")

        if not user.is_active:
            raise serializers.ValidationError("User account is not active")

        refresh = RefreshToken.for_user(user)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }
    


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("User with this email does not exist.")
        return value

    def create(self, validated_data):
        user = User.objects.get(email=validated_data['email'])
        code = str(random.randint(1000, 9999))

        EmailVerification.objects.create(user=user, code=code)

        send_mail(
            'Password Reset Code',
            f'Your password reset code is {code}',
            'noreply@example.com',
            [user.email],
            fail_silently=False
        )
        return validated_data
    

class PasswordResetConfirmSerializer(serializers.Serializer):
    email = serializers.EmailField()
    code = serializers.CharField()
    new_password = serializers.CharField(write_only=True, validators=[validate_password])
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match.")
        return data

    def save(self, **kwargs):
        try:
            user = User.objects.get(email=self.validated_data['email'])
            verification = EmailVerification.objects.filter(
                user=user, code=self.validated_data['code']).latest('created_at')

            if verification.is_expired():
                raise serializers.ValidationError("Code has expired.")

            user.set_password(self.validated_data['new_password'])
            user.save()

            # Optionally, delete used codes
            EmailVerification.objects.filter(user=user).delete()

        except (User.DoesNotExist, EmailVerification.DoesNotExist):
            raise serializers.ValidationError("Invalid code or email.")
        


class ProfileSerializer(serializers.ModelSerializer):
    # Mapping the user fields (first_name, last_name) to the profile serializer
    first_name = serializers.CharField(source='user.first_name', required=False, allow_blank=True)
    last_name = serializers.CharField(source='user.last_name', required=False, allow_blank=True)
    email = serializers.EmailField(source='user.email', read_only=True, validators=[UniqueValidator(queryset=User.objects.all(), message="This email is already in use.")])
    
    # Profile fields
    phone = serializers.CharField(required=False, allow_blank=True)
    image = serializers.ImageField(required=False, allow_null=True)

    class Meta:
        model = Profile
        fields = ["first_name", "last_name", "email", "phone", "image"]

    def update(self, instance, validated_data):
        """
        Custom update method to handle updating both user and profile fields.
        """
        # Handle the user fields (first_name, last_name)
        user_data = validated_data.pop('user', {})
        user = instance.user

        # Update user fields if provided in the request
        if 'first_name' in user_data:
            user.first_name = user_data['first_name']
        if 'last_name' in user_data:
            user.last_name = user_data['last_name']
        user.save()

        # Now update the profile fields (phone, image)
        return super().update(instance, validated_data)
