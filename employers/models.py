from django.db import models
from django.core.validators import RegexValidator
from authentication.models import User

class Employer(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='employers')
    company_name = models.CharField(max_length=100)
    contact_person_name = models.CharField(max_length=100)
    email = models.EmailField()
    phone_number = models.CharField(
        max_length=14,
        validators=[
            RegexValidator(
                regex=r'^0\d{10}$',
                message="Phone number must be 11 digits starting with '0' (e.g., 01775289775)."
            ),
            RegexValidator(
                regex=r'^0(13|14|15|16|17|18|19)\d{8}$',
                message="Phone number must start with a valid Bangladeshi mobile prefix (013, 014, 015, 016, 017, 018, 019)."
            )
        ]
    )
    address = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.company_name

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['user', 'email'],
                name='unique_user_email'
            )
        ]