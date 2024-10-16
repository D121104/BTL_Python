import random
from django.core.mail import EmailMessage, send_mail
from .models import User, OneTimePassword
from django.conf import settings

def generateOTP():
    otp = random.randint(100000, 999999)
    return otp

def send_otp_email(email):
    subject = 'Your OTP for registration'
    otp_code = generateOTP()
    message = f'Your OTP is {otp_code}'
    user = User.objects.get(email=email)
    curent_site = "myAuth.com"
    from_email='temp49075@gmail.com'

    OneTimePassword.objects.create(user=user, otp=otp_code)
    try: 
        send_email = EmailMessage(subject, message, from_email, [email])
        send_email.send(fail_silently=False)
    except Exception as e:
        print(e)
        return False
    
def send_normal_email(data):
    email = EmailMessage(
        subject=data['subject'],
        body=data['body'],
        from_email=settings.EMAIL_HOST_USER,
        to=[data['to_email']]
    )
    email.send(fail_silently=False)