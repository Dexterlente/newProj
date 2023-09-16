import smtplib
from email.mime.text import MIMEText
from django.conf import settings
from celery import shared_task

from django.utils.http import urlsafe_base64_encode
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes

url = "http://localhost:2000/"

from accounts.models import User  # Import your custom User model here

@shared_task(bind=True, max_retries=20)
def send_register_mail(self, user, key):
    body = """<p>
    Hello from E-commerce!<br><br>

    Confirmation Mail: %s

    You can see more details in this link: %saccount-confirm-email/%s<br><br>

    Thank you from E-commerce! <br><br>
    <p>""" % (
        user.username,
        url,
        key,
    )

    subject = "Registeration Mail"
    recipients = [user.email]

    try:
        send_email(body, subject, recipients, "html")
        return "Email Is Sent"
    except Exception as e:
        print("Email not sent ", e)
        raise self.retry(exc=e, countdown=25200)


@shared_task(bind=True, max_retries=20)
def send_reset_password_email(self, user):
    # try:
    #     user = User.objects.get(id=user_id)
    # except User.DoesNotExist:
    #     # Handle the case where the user doesn't exist
    #     return

    body = """
    hello %s, 
    deexter You're receiving this e-mail because you or someone else has requested a password for your user account.
    It can be safely ignored if you did not request a password reset. Click the link below to reset your password.

    reset url : %sretypepassword/%s/%s
    Reset URL: %saccounts/authentication/password/reset/confirm/%s/%s
    reset the password
    """ % (
        user.username,
        url,
        urlsafe_base64_encode(force_bytes(user.pk)).decode(),
        default_token_generator.make_token(user),
    )
    subject = "Reset password Mail"
    recipients = [user.email]
    try:
        send_email(body, subject, recipients, "plain")
        return "Email Is Sent"
    except Exception as e:
        print("Email not sent ", e)
        raise self.retry(exc=e, countdown=25200)


def send_email(body, subject, recipients, body_type="plain"):
    session = smtplib.SMTP("smtp.gmail.com", getattr(settings, "EMAIL_PORT", None))
    session.starttls()
    session.login(
        getattr(settings, "EMAIL_HOST_USER", None),
        getattr(settings, "EMAIL_HOST_PASSWORD", None),
    )
    sender = "gracelente@localhost"
    msg = MIMEText(body, body_type)
    msg["subject"] = subject
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    session.sendmail(sender, recipients, msg.as_string())