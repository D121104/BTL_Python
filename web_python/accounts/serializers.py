from django.forms import ValidationError
from rest_framework import serializers
from .models import User
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import smart_str, smart_bytes, force_bytes, force_str
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .utils import send_normal_email
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.contrib.auth.hashers import make_password


class UserRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=50, min_length=6, write_only=True)
    repeat_password = serializers.CharField(max_length=50, min_length=6, write_only=True)

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'password', 'repeat_password']
        
    def validate(self, attrs):
        password = attrs.get('password')
        repeat_password = attrs.get('repeat_password')
        if len(password) < 6:
            raise serializers.ValidationError('Password must be at least 6 characters long.')
        if password != repeat_password:
            raise serializers.ValidationError('Passwords do not match')
        return attrs

    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            password=validated_data['password']
        )
        return user
    
class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    password = serializers.CharField(max_length=50, write_only=True)
    full_name = serializers.CharField(max_length=255, read_only=True)
    access_token = serializers.CharField(max_length=255, read_only=True)
    refresh_token = serializers.CharField(max_length=255, read_only=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'full_name', 'access_token', 'refresh_token']
        
    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        request = self.context.get('request')
        user = authenticate(request=request, email=email, password=password)
        if not user:
            raise AuthenticationFailed('Wrong email or password', 401)
        if not user.is_verified:
            raise AuthenticationFailed('Email is not verified')
        tokens = user.tokens()
        attrs['user'] = user
        return attrs

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=4, max_length=255)
    
    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')
        user = User.objects.filter(email=email)
        if not user.exists():
            raise serializers.ValidationError('No user with this email address')
            
        user = user.first()
        uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
        token = PasswordResetTokenGenerator().make_token(user)
        request = self.context.get('request')
        site_domain = get_current_site(request).domain
        relative_link = reverse('password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})
        abs_url = f'http://{site_domain}{relative_link}'
        email_body = f'Hello, \nClick on the link below to reset your password \n{abs_url}\nYour new password will be sent to your email address\nIf you did not request a password reset, please ignore this email\nThank you'
        data = {
            'body': email_body,
            'subject': 'Reset your password',
            'to_email': user.email
        }
        send_normal_email(data)
        return super().validate(attrs)
    
class SetNewPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=4, max_length=255)
    current_password = serializers.CharField(min_length=6, max_length=50, write_only=True)
    new_password = serializers.CharField(min_length=6, max_length=50, write_only=True)
    confirm_new_password = serializers.CharField(min_length=6, max_length=50, write_only=True)

    class Meta:
        fields = ['email','current_password', 'new_password', 'confirm_new_password']

    def validate(self, attrs):
        email = attrs.get('email')
        current_password = attrs.get('current_password')
        new_password = attrs.get('new_password')
        confirm_new_password = attrs.get('confirm_new_password')
        try:
            user = User.objects.get(email=email)
            # print(user)
            if not user.check_password(current_password):
                raise AuthenticationFailed('Current password is incorrect', 401)
            if new_password != confirm_new_password:
                raise AuthenticationFailed('Passwords do not match', 401)
            return super().validate(attrs)
        except User.DoesNotExist:
            raise AuthenticationFailed('User not found', 404)
        except Exception as e:
            raise AuthenticationFailed(f'An error occurred. Email : {email}', 401)
        
    def create(self, validated_data):
        email = validated_data.get('email')
        new_password = validated_data.get('new_password')
        user = User.objects.get(email=email)
        user.set_password(new_password)
        user.save()
        return user
       

class LogoutUserSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()

    default_error_messages = {
        'invalid_token': 'Token is invalid or expired'
    }

    def validate(self, attrs):
        self.token = attrs.get('refresh_token')
        return attrs
    
    def save(self, **kwargs):
        try:
            token = RefreshToken(self.token)
            token.blacklist()
        except TokenError as e:
            self.fail('invalid_token')
        
class VerifyUserEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=4, max_length=255)
    
    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')
        user = User.objects.filter(email=email)
        if not user.exists():
            raise serializers.ValidationError('No user with this email address')
            
        return super().validate(attrs)