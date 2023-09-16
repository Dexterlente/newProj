# celery.py (or celeryconfig.py)
from celery import Celery
import os

# Set the default Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'auth.settings')

# Create a Celery instance
app = Celery('auth')

# Load the Celery configuration from Django settings
app.config_from_object('django.conf:settings', namespace='CELERY')

# Autodiscover tasks in your Django app
app.autodiscover_tasks()

# Broker is needed