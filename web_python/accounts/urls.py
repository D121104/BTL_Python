from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.RegisterView.as_view(), name='register'),
    path('verify-email/<str:email>', views.VerifyUserEmail.as_view(), name='verify-email'),
    path('login/', views.LoginUserView.as_view(), name='login'),
    path('password-reset/', views.PasswordResetRequestView.as_view(), name='password-reset'),
    path('password-reset-confirm/', views.PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    path('password-reset-confirm/<str:uidb64>/<str:token>/', views.PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    path('set-new-password/', views.SetNewPasswordView.as_view(), name='set-new-password'),
    path('logout/', views.LogoutUserView.as_view(), name='logout'),
]