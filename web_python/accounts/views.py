from django.shortcuts import render, redirect
from .models import User, OneTimePassword
from django.template.response import TemplateResponse
from django.http import JsonResponse, HttpResponse
from django.forms.models import model_to_dict
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from .serializers import UserRegisterSerializer, UserLoginSerializer, PasswordResetRequestSerializer, SetNewPasswordSerializer, LogoutUserSerializer, VerifyUserEmailSerializer
from rest_framework.generics import GenericAPIView
from .utils import send_otp_email, send_normal_email
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import smart_str, smart_bytes, DjangoUnicodeDecodeError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from .forms import UserRegisterForm, UserLoginForm, PasswordResetRequestForm, SetNewPasswordForm
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken
from django.forms import ValidationError
import uuid

class RegisterView(GenericAPIView):
    serializer_class = UserRegisterSerializer
    
    def post(self, request):
        user_data = request.data
        serializer = self.get_serializer(data=user_data)
        form = UserRegisterForm(request.data)
        if serializer.is_valid() and form.is_valid():
            serializer.save()
            user = serializer.data
            send_otp_email(user['email'])
            return TemplateResponse(request, 'register.html', {
                'form': form,
                'data': user,
                'message': 'User created successfully. Verify your email to activate your account'
            }, status=status.HTTP_201_CREATED)
        else:
            form = UserRegisterForm(request.data)
            return TemplateResponse(request, 'register.html', {
                'form': form,
            }, status=status.HTTP_400_BAD_REQUEST)
    
    def get(self, request):
        form = UserRegisterForm()
        serializer = self.get_serializer()
        return TemplateResponse(request, 'register.html', {'form' : form} ,status=status.HTTP_200_OK)

class VerifyUserEmail(GenericAPIView):
    serializer_class = VerifyUserEmailSerializer
    def post(self, request):
        try:
            otp = request.data.get('otp')
            user_pass = OneTimePassword.objects.get(otp=otp)
            user = user_pass.user
            if not user.is_verified:
                user.is_verified = True
                user.save()
                return Response('Email verified successfully', status=status.HTTP_200_OK)
            return Response('Email already verified', status=status.HTTP_400_BAD_REQUEST)
        except OneTimePassword.DoesNotExist:
            return Response('Invalid OTP', status=status.HTTP_400_BAD_REQUEST)
    
class LoginUserView(GenericAPIView):
    serializer_class = UserLoginSerializer

    def post(self, request):
        user_data = request.data
        serializer = self.serializer_class(data=user_data, context={'request': request})
        form = UserLoginForm(request.data)
        try:
            serializer.is_valid(raise_exception=True)
            user = serializer.validated_data['user']

            refresh = RefreshToken.for_user(user)
            serializer.is_valid(raise_exception=True)
            user = serializer.validated_data['user']

            refresh = RefreshToken.for_user(user)
            response = Response({
                'message': 'Login successful',
                'tokens': {
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                }
            }, status=status.HTTP_200_OK)
            request.session['access_token'] = str(refresh.access_token)
            request.session['refresh_token'] = str(refresh)
            request.session['user'] = {
                'id' : user.id,
                'first_name' : user.first_name,
                'last_name' : user.last_name,
            }
            return redirect('/')

        except AuthenticationFailed as e:
            form = UserLoginForm(request.data)
            form.add_error(None, str(e))
            return TemplateResponse(request, 'login.html', {
                'form': form,
            }, status=status.HTTP_400_BAD_REQUEST)
    
    def get(self, request):
        form = UserLoginForm()
        return TemplateResponse(request, 'login.html', {'form': form}, status=status.HTTP_200_OK)

class PasswordResetRequestView(GenericAPIView):
    serializer_class = PasswordResetRequestSerializer
    def post(self, request):
        user_data = request.data
        form = PasswordResetRequestForm(user_data)
        serializer = self.serializer_class(data=user_data, context={'request': request})
        try:
            serializer.is_valid(raise_exception=False)
        except ValidationError as e:
            form.add_error(None, str(e))
            return TemplateResponse(request, 'password_reset.html', {
                'form': form,
            }, status=status.HTTP_400_BAD_REQUEST)
        
        return TemplateResponse(request, 'password_reset.html',{
                'form': form,
                'message_': 'Password reset email sent'
            }, status=status.HTTP_200_OK)
      
        
    def get(self, request):
        form = PasswordResetRequestForm()
        return TemplateResponse(request, 'password_reset.html', {'form': form}, status=status.HTTP_200_OK)
    
class PasswordResetConfirmView(GenericAPIView):
    def get(self, request, uidb64, token):
        try:
            user_id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=user_id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                return TemplateResponse(request, 'password_reset.html', {
                    'message': 'Token is invalid or has expired'
                }, status=status.HTTP_400_BAD_REQUEST)
            new_password = uuid.uuid4().hex
            user.set_password(new_password)
            user.save()
            send_normal_email({
                'subject': 'Password reset successful',
                'body': f'Your new password is {new_password}',
                'to_email': user.email
            })
            return redirect('/api/auth/login')
        except DjangoUnicodeDecodeError as e:
            return TemplateResponse(request, 'password_reset_confirm.html', {
                'message': 'Token is invalid or has expired'
            }, status=status.HTTP_400_BAD_REQUEST)
        
class SetNewPasswordView(GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = SetNewPasswordSerializer

    def get(self, request):
        form = SetNewPasswordForm()
        return TemplateResponse(request, 'set_new_password.html', {
            'form' : form
        }, status=status.HTTP_200_OK)
    
    def post(self, request):
        refresh_token = request.session.get('refresh_token')
        if not refresh_token:
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                refresh_token = auth_header.split(' ')[1]

        if not refresh_token:
            return Response({'detail': 'Refresh token is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        user_data = request.data
        form = SetNewPasswordForm(user_data)
        serializer = self.serializer_class(data=user_data)
        try:
            serializer.is_valid(raise_exception=False)
        except ValidationError as e:
            form.add_error(None, str(e))
            return TemplateResponse(request, 'set_new_password.html', {
                'form': form,
            }, status=status.HTTP_400_BAD_REQUEST)
        serializer.save()
        return redirect('/')


class LogoutUserView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        refresh_token = request.session.get('refresh_token')
        if not refresh_token:
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                refresh_token = auth_header.split(' ')[1]

        if not refresh_token:
            return Response({'detail': 'Refresh token is required'}, status=status.HTTP_400_BAD_REQUEST)
        serializer = LogoutUserSerializer(data={'refresh_token': refresh_token})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        request.session.flush()
        return TemplateResponse(request, 'home.html', {}, status=status.HTTP_200_OK)

    # def post(self, request):
    #     refresh_token = request.data.get('refresh_token')
    #     if not refresh_token:
    #         auth_header = request.headers.get('Authorization')
    #         if auth_header and auth_header.startswith('Bearer '):
    #             refresh_token = auth_header.split(' ')[1]

    #     if not refresh_token:
    #         return Response({'detail': 'Refresh token is required'}, status=status.HTTP_400_BAD_REQUEST)
    #     serializer = LogoutUserSerializer(data={'refresh_token': refresh_token})
    #     serializer.is_valid(raise_exception=True)
    #     serializer.save()
    #     return TemplateResponse(request, 'home.html', {}, status=status.HTTP_200_OK)

class ForgotPasswordView(GenericAPIView):
    def get(self, request):
        return TemplateResponse(request, 'forgot_password.html', {}, status=status.HTTP_200_OK)

def home(request):
    return render(request, 'index.html')

def quiz(request):
    return render(request, 'quiz.html')

def leaderboard_(request):
    return render(request, 'leaderboard_.html')

