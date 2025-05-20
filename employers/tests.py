from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient, APITestCase
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from .models import Employer
from .serializers import EmployerSerializer
from authentication.models import User

class EmployerModelTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            email='test@example.com',
            password='Test@1234'
        )
        self.employer_data = {
            'user': self.user,
            'company_name': 'Test Company',
            'contact_person_name': 'John Doe',
            'email': 'contact@company.com',
            'phone_number': '+8801775289775',
            'address': '123 Test Street, Dhaka'
        }

    def test_create_employer_valid(self):
        """MODEL_001: Test creating an employer with valid data."""
        employer = Employer.objects.create(**self.employer_data)
        self.assertEqual(employer.company_name, self.employer_data['company_name'])
        self.assertEqual(employer.phone_number, self.employer_data['phone_number'])
        self.assertEqual(employer.email, self.employer_data['email'])

    def test_create_employer_invalid_phone(self):
        """MODEL_002: Test creating an employer with invalid phone number."""
        invalid_data = self.employer_data.copy()
        invalid_data['phone_number'] = '12345'  # Invalid format
        with self.assertRaises(Exception):
            Employer.objects.create(**invalid_data)

    def test_unique_user_email(self):
        """MODEL_003: Test unique constraint on user and email."""
        Employer.objects.create(**self.employer_data)
        duplicate_data = self.employer_data.copy()
        duplicate_data['phone_number'] = '+8801775289776'  # Different phone
        with self.assertRaises(Exception):
            Employer.objects.create(**duplicate_data)

    def test_str_representation(self):
        """MODEL_004: Test employer string representation."""
        employer = Employer.objects.create(**self.employer_data)
        self.assertEqual(str(employer), self.employer_data['company_name'])

class EmployerSerializerTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            email='test@example.com',
            password='Test@1234'
        )
        self.valid_data = {
            'company_name': 'Test Company',
            'contact_person_name': 'John Doe',
            'email': 'contact@company.com',
            'phone_number': '+8801775289775',
            'address': '123 Test Street, Dhaka'
        }
        self.context = {'request': type('Request', (), {'user': self.user})()}

    def test_valid_serializer(self):
        """SERIALIZER_001: Test serializer with valid data."""
        serializer = EmployerSerializer(data=self.valid_data, context=self.context)
        self.assertTrue(serializer.is_valid())
        employer = serializer.save(user=self.user)
        self.assertEqual(employer.phone_number, '+8801775289775')

    def test_phone_number_formats(self):
        """SERIALIZER_002: Test different valid phone number formats."""
        phone_formats = [
            '+8801775289775',
            '01775289775',
            '8801775289775',
            '1775289775'
        ]
        for phone in phone_formats:
            data = self.valid_data.copy()
            data['phone_number'] = phone
            serializer = EmployerSerializer(data=data, context=self.context)
            self.assertTrue(serializer.is_valid(), msg=f"Failed for phone: {phone}")
            employer = serializer.save(user=self.user)
            self.assertEqual(employer.phone_number, '+8801775289775')

    def test_invalid_phone_prefix(self):
        """SERIALIZER_003: Test phone number with invalid Bangladeshi prefix."""
        data = self.valid_data.copy()
        data['phone_number'] = '+8801234567890'  # Invalid prefix
        serializer = EmployerSerializer(data=data, context=self.context)
        self.assertFalse(serializer.is_valid())
        self.assertIn('phone_number', serializer.errors)
        self.assertIn('Phone number must start with a valid Bangladeshi mobile prefix', str(serializer.errors['phone_number']))

    def test_invalid_phone_format(self):
        """SERIALIZER_004: Test phone number with invalid format."""
        data = self.valid_data.copy()
        data['phone_number'] = '12345'
        serializer = EmployerSerializer(data=data, context=self.context)
        self.assertFalse(serializer.is_valid())
        self.assertIn('phone_number', serializer.errors)
        self.assertIn('Phone number must be a valid Bangladeshi number', str(serializer.errors['phone_number']))

    def test_empty_phone_number(self):
        """SERIALIZER_005: Test empty phone number."""
        data = self.valid_data.copy()
        data['phone_number'] = ''
        serializer = EmployerSerializer(data=data, context=self.context)
        self.assertFalse(serializer.is_valid())
        self.assertIn('phone_number', serializer.errors)
        self.assertEqual(serializer.errors['phone_number'][0], 'Phone number cannot be empty.')

    def test_duplicate_email(self):
        """SERIALIZER_006: Test duplicate email for the same user."""
        Employer.objects.create(user=self.user, **self.valid_data)
        data = self.valid_data.copy()
        data['phone_number'] = '+8801775289776'
        serializer = EmployerSerializer(data=data, context=self.context)
        self.assertFalse(serializer.is_valid())
        self.assertIn('email', serializer.errors)
        self.assertEqual(serializer.errors['email'][0], 'This email is already in use by another employer for this user.')

    def test_invalid_email_format(self):
        """SERIALIZER_007: Test invalid email format."""
        data = self.valid_data.copy()
        data['email'] = 'invalid-email'
        serializer = EmployerSerializer(data=data, context=self.context)
        self.assertFalse(serializer.is_valid())
        self.assertIn('email', serializer.errors)
        self.assertEqual(serializer.errors['email'][0], 'Invalid email format.')

class EmployerViewsTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = get_user_model().objects.create_user(
            email='test@example.com',
            password='Test@1234'
        )
        self.other_user = get_user_model().objects.create_user(
            email='other@example.com',
            password='Test@1234'
        )
        self.employer_data = {
            'company_name': 'Test Company',
            'contact_person_name': 'John Doe',
            'email': 'contact@company.com',
            'phone_number': '+8801775289775',
            'address': '123 Test Street, Dhaka'
        }
        self.login_data = {
            'email': 'test@example.com',
            'password': 'Test@1234'
        }

    def authenticate(self):
        """Helper to authenticate the client."""
        response = self.client.post('/api/auth/login/', self.login_data)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {response.data["access"]}')

    def test_create_employer_valid(self):
        """VIEW_001: Test creating an employer with valid data."""
        self.authenticate()
        response = self.client.post('/api/employers/', self.employer_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['phone_number'], '+8801775289775')

    def test_create_employer_phone_formats(self):
        """VIEW_002: Test creating an employer with different phone number formats."""
        phone_formats = [
            '+8801775289775',
            '01775289775',
            '8801775289775',
            '1775289775'
        ]
        self.authenticate()
        for phone in phone_formats:
            data = self.employer_data.copy()
            data['phone_number'] = phone
            response = self.client.post('/api/employers/', data)
            self.assertEqual(response.status_code, status.HTTP_201_CREATED, msg=f"Failed for phone: {phone}")
            self.assertEqual(response.data['phone_number'], '+8801775289775')

    def test_create_employer_invalid_phone(self):
        """VIEW_003: Test creating an employer with invalid phone number."""
        self.authenticate()
        data = self.employer_data.copy()
        data['phone_number'] = '+8801234567890'  # Invalid prefix
        response = self.client.post('/api/employers/', data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('phone_number', response.data)

    def test_list_employers(self):
        """VIEW_004: Test listing employers for authenticated user."""
        self.authenticate()
        Employer.objects.create(user=self.user, **self.employer_data)
        response = self.client.get('/api/employers/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['email'], self.employer_data['email'])

    def test_retrieve_employer(self):
        """VIEW_005: Test retrieving a specific employer."""
        self.authenticate()
        employer = Employer.objects.create(user=self.user, **self.employer_data)
        response = self.client.get(f'/api/employers/{employer.id}/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['phone_number'], '+8801775289775')

    def test_update_employer(self):
        """VIEW_006: Test updating an employer."""
        self.authenticate()
        employer = Employer.objects.create(user=self.user, **self.employer_data)
        update_data = self.employer_data.copy()
        update_data['phone_number'] = '01775289776'
        response = self.client.put(f'/api/employers/{employer.id}/', update_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['phone_number'], '+8801775289776')

    def test_delete_employer(self):
        """VIEW_007: Test deleting an employer."""
        self.authenticate()
        employer = Employer.objects.create(user=self.user, **self.employer_data)
        response = self.client.delete(f'/api/employers/{employer.id}/')
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(Employer.objects.filter(id=employer.id).exists())

    def test_unauthenticated_access(self):
        """VIEW_008: Test accessing endpoints without authentication."""
        response = self.client.get('/api/employers/')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_access_other_user_employer(self):
        """VIEW_009: Test accessing another user's employer."""
        employer = Employer.objects.create(user=self.user, **self.employer_data)
        other_login_data = {'email': 'other@example.com', 'password': 'Test@1234'}
        response = self.client.post('/api/auth/login/', other_login_data)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {response.data["access"]}')
        response = self.client.get(f'/api/employers/{employer.id}/')
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)