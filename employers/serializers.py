from rest_framework import serializers
from .models import Employer
import re
import logging

logger = logging.getLogger(__name__)

class ValidatedPhoneNumberField(serializers.CharField):
    def to_internal_value(self, data):
        logger.debug(f"ValidatedPhoneNumberField to_internal_value: {data}")
        phone_number = str(data).strip().replace(" ", "")
        if phone_number.startswith("+880"):
            phone_number = "0" + phone_number[4:]
        elif not phone_number.startswith("0"):
            raise serializers.ValidationError("Phone number must start with '0' or '+880'.")
        if not re.match(r"^0\d{10}$", phone_number):
            raise serializers.ValidationError("Phone number must be 11 digits starting with '0'.")
        return phone_number

    def to_representation(self, value):
        logger.debug(f"ValidatedPhoneNumberField to_representation: {value}")
        if value:
            phone_number = str(value).strip().replace(" ", "")
            if phone_number.startswith("+880"):
                phone_number = "0" + phone_number[4:]
            elif phone_number.startswith("880"):
                phone_number = "0" + phone_number[3:]
            elif not phone_number.startswith("0"):
                phone_number = "0" + phone_number
            return phone_number
        return value

class EmployerSerializer(serializers.ModelSerializer):
    phone_number = ValidatedPhoneNumberField(max_length=14)

    class Meta:
        model = Employer
        fields = ['id', 'company_name', 'contact_person_name', 'email', 
                  'phone_number', 'address', 'created_at']
        read_only_fields = ['created_at', 'user']

    def validate_email(self, value):
        """Validate email format and uniqueness."""
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_regex, value):
            raise serializers.ValidationError("Invalid email format.")
        disposable_domains = ['mailinator.com', 'tempmail.com', '10minutemail.com']
        domain = value.split('@')[1]
        if domain in disposable_domains:
            raise serializers.ValidationError("Disposable email addresses are not allowed.")
        request = self.context.get('request')
        if request and hasattr(request, 'user'):
            if self.instance:
                if Employer.objects.filter(user=request.user, email=value).exclude(pk=self.instance.pk).exists():
                    raise serializers.ValidationError("This email is already in use by another employer for this user.")
            else:
                if Employer.objects.filter(user=request.user, email=value).exists():
                    raise serializers.ValidationError("This email is already in use by another employer for this user.")
        return value

    def validate_company_name(self, value):
        """Ensure company name is not empty and contains valid characters."""
        if not value.strip():
            raise serializers.ValidationError("Company name cannot be empty.")
        if len(value) < 2:
            raise serializers.ValidationError("Company name must be at least 2 characters long.")
        if not re.match(r'^[\w\s\-\'&]+$', value):
            raise serializers.ValidationError("Company name contains invalid characters.")
        return value

    def validate_contact_person_name(self, value):
        """Ensure contact person name is valid."""
        if not value.strip():
            raise serializers.ValidationError("Contact person name cannot be empty.")
        if len(value) < 2:
            raise serializers.ValidationError("Contact person name must be at least 2 characters long.")
        if not re.match(r'^[\w\s\-\']+$', value):
            raise serializers.ValidationError("Contact person name contains invalid characters.")
        return value

    def validate_address(self, value):
        """Ensure address is not empty."""
        if not value.strip():
            raise serializers.ValidationError("Address cannot be empty.")
        return value