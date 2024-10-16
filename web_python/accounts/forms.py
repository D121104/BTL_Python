from django import forms
from .models import User

class UserRegisterForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)
    repeat_password = forms.CharField(widget=forms.PasswordInput, label='Repeat Password')

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'password', 'repeat_password']

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        repeat_password = cleaned_data.get('repeat_password')
        if len(password) < 6:
            raise forms.ValidationError('Password must be at least 6 characters long.')
        if password != repeat_password:
            raise forms.ValidationError('Passwords do not match')
        return cleaned_data

class UserLoginForm(forms.Form):
    email = forms.EmailField()
    password = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        fields = ['email', 'password']
    
    # def clean(self):
    #     cleaned_data = super().clean()
    #     email = cleaned_data.get('email')
    #     password = cleaned_data.get('password')
    #     user = User.objects.filter(email=email).first()
    #     if not user:
    #         raise forms.ValidationError('User does not exist')
    #     if not user.check_password(password):
    #         raise forms.ValidationError('Invalid password')
    #     return cleaned_data
class PasswordResetRequestForm(forms.Form):
    email = forms.EmailField()

    class Meta:
        fields = ['email']
    
    def clean(self):
        cleaned_data = super().clean()
        email = cleaned_data.get('email')
        user = User.objects.filter(email=email).first()
        if not user:
            raise forms.ValidationError('User does not exist')
        return cleaned_data

class SetNewPasswordForm(forms.Form):
    email = forms.EmailField(widget=forms.EmailInput, label='Email')
    current_password = forms.CharField(widget=forms.PasswordInput, label='Current Password')
    new_password = forms.CharField(widget=forms.PasswordInput, label='New Password')
    confirm_new_password = forms.CharField(widget=forms.PasswordInput, label='Confirm New Password')

    class Meta:
        fields = ['Email','Current Password', 'New Password', 'Confirm New Password']

    def clean(self):
        cleaned_data = super().clean()
        email = cleaned_data.get('email')
        current_password = cleaned_data.get('current_password')
        new_password = cleaned_data.get('new_password')
        confirm_new_password = cleaned_data.get('confirm_new_password')
        if len(new_password) < 6:
            raise forms.ValidationError('Password must be at least 6 characters long.')
        if new_password != confirm_new_password:
            raise forms.ValidationError('Passwords do not match')
        return cleaned_data
