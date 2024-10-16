from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from .managers import UserManager
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.validators import MinLengthValidator

# Create your models here.
class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(max_length=200, unique=True, verbose_name='Email Address')
    password = models.CharField(max_length=50)
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_superuser = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_login = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    objects = UserManager()
    
    def __str__(self):
        return self.email
    
    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }
    
    @property
    def get_full_name(self):
        return self.first_name + ' ' + self.last_name
    
    def set_password(self, raw_password: str | None) -> None:
        return super().set_password(raw_password)
    
    def set_verified(self):
        self.is_verified = True
        self.save()
    
    


class OneTimePassword(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.otp
    