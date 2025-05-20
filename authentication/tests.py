from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient, APITestCase
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from authentication.models import User
from authentication.serializers import RegisterSerializer, LoginSerializer
import re

class UserModelTests(TestCase):
    def setUp(self):
        self.user_model = get_user_model()
        self.user_data = {
            'email': 'test@example.com',
            'first_name': 'John',
            'last_name': 'Doe',
            'password': 'Test@1234'
        }

    def test_create_user_valid(self):
        """MODEL_001: Test creating a regular user with valid data."""
        user = self.user_model.objects.create_user(
            email=self.user_data['email'],
            password=self.user_data['password'],
            first_name=self.user_data['first_name'],
            last_name=self.user_data['last_name']
        )
        self.assertEqual(user.email, self.user_data['email'])
        self.assertTrue(user.check_password(self.user_data['password']))
        self.assertEqual(user.first_name, self.user_data['first_name'])
        self.assertEqual(user.last_name, self.user_data['last_name'])
        self.assertTrue(user.is_active)
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)

    def test_create_user_no_email(self):
        """MODEL_002: Test creating a user without an email raises ValueError."""
        with self.assertRaises(ValueError):
            self.user_model.objects.create_user(email='', password='Test@1234')

    def test_create_user_duplicate_email(self):
        """MODEL_003: Test creating a user with a duplicate email raises an error."""
        self.user_model.objects.create_user(**self.user_data)
        with self.assertRaises(Exception):
            self.user_model.objects.create_user(**self.user_data)

    def test_create_user_special_characters(self):
        """MODEL_004: Test creating a user with special characters in names."""
        user = self.user_model.objects.create_user(
            email='special@example.com',
            password='Test@1234',
            first_name='John-Doe',
            last_name='O\'Connor'
        )
        self.assertEqual(user.first_name, 'John-Doe')
        self.assertEqual(user.last_name, 'O\'Connor')

    def test_create_superuser(self):
        """MODEL_005: Test creating a superuser with valid data."""
        superuser = self.user_model.objects.create_superuser(
            email=self.user_data['email'],
            password=self.user_data['password']
        )
        self.assertTrue(superuser.is_staff)
        self.assertTrue(superuser.is_superuser)
        self.assertTrue(superuser.is_active)

    def test_user_str(self):
        """MODEL_006: Test the string representation of the user."""
        user = self.user_model.objects.create_user(**self.user_data)
        self.assertEqual(str(user), self.user_data['email'])

class RegisterSerializerTests(TestCase):
    def setUp(self):
        self.valid_data = {
            'email': 'test@example.com',
            'first_name': 'John',
            'last_name': 'Doe',
            'password': 'Test@1234',
            'password2': 'Test@1234'
        }
        self.invalid_email_data = {
            'email': 'invalid-email',
            'first_name': 'John',
            'last_name': 'Doe',
            'password': 'Test@1234',
            'password2': 'Test@1234'
        }
        self.weak_password_data = {
            'email': 'test@example.com',
            'first_name': 'John',
            'last_name': 'Doe',
            'password': 'weak',
            'password2': 'weak'
        }
        self.mismatch_password_data = {
            'email': 'test@example.com',
            'first_name': 'John',
            'last_name': 'Doe',
            'password': 'Test@1234',
            'password2': 'Test@5678'
        }
        self.disposable_email_data = {
            'email': 'test@mailinator.com',
            'first_name': 'John',
            'last_name': 'Doe',
            'password': 'Test@1234',
            'password2': 'Test@1234'
        }
        self.empty_field_data = {
            'email': '',
            'first_name': '',
            'last_name': '',
            'password': 'Test@1234',
            'password2': 'Test@1234'
        }
        self.password_with_spaces_data = {
            'email': 'test@example.com',
            'first_name': 'John',
            'last_name': 'Doe',
            'password': 'Test @ 1234',
            'password2': 'Test @ 1234'
        }
        self.max_length_data = {
            'email': 'a' * 100 + '@example.com',
            'first_name': 'A' * 31,
            'last_name': 'B' * 31,
            'password': 'Test@1234',
            'password2': 'Test@1234'
        }

    def test_valid_serializer(self):
        """SERIALIZER_001: Test serializer with valid data."""
        serializer = RegisterSerializer(data=self.valid_data)
        self.assertTrue(serializer.is_valid())
        user = serializer.save()
        self.assertEqual(user.email, self.valid_data['email'])
        self.assertTrue(user.check_password(self.valid_data['password']))

    def test_invalid_email_format(self):
        """SERIALIZER_002: Test serializer with invalid email format."""
        serializer = RegisterSerializer(data=self.invalid_email_data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('email', serializer.errors)
        self.assertEqual(serializer.errors['email'][0], 'Invalid email format')

    def test_weak_password(self):
        """SERIALIZER_003: Test serializer with weak password."""
        serializer = RegisterSerializer(data=self.weak_password_data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('password', serializer.errors)
        self.assertIn('Password must be at least 8 characters long', str(serializer.errors['password']))

    def test_password_mismatch(self):
        """SERIALIZER_004: Test serializer with mismatched passwords."""
        serializer = RegisterSerializer(data=self.mismatch_password_data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('password', serializer.errors)
        self.assertEqual(serializer.errors['password'][0], 'Passwords must match')

    def test_disposable_email(self):
        """SERIALIZER_005: Test serializer with disposable email domain."""
        serializer = RegisterSerializer(data=self.disposable_email_data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('email', serializer.errors)
        self.assertEqual(serializer.errors['email'][0], 'Disposable email addresses are not allowed')

    def test_duplicate_email(self):
        """SERIALIZER_006: Test serializer with already registered email."""
        self.user_model.objects.create_user(**self.valid_data)
        serializer = RegisterSerializer(data=self.valid_data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('email', serializer.errors)
        self.assertEqual(serializer.errors['email'][0], 'Email is already registered')

    def test_empty_fields(self):
        """SERIALIZER_007: Test serializer with empty email field."""
        serializer = RegisterSerializer(data=self.empty_field_data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('email', serializer.errors)
        self.assertEqual(serializer.errors['email'][0], 'This field may not be blank.')

    def test_password_with_spaces(self):
        """SERIALIZER_008: Test serializer with password containing spaces."""
        serializer = RegisterSerializer(data=self.password_with_spaces_data)
        self.assertTrue(serializer.is_valid())  # Spaces are allowed unless explicitly restricted
        user = serializer.save()
        self.assertTrue(user.check_password(self.password_with_spaces_data['password']))

    def test_max_length_fields(self):
        """SERIALIZER_009: Test serializer with fields exceeding maximum length."""
        serializer = RegisterSerializer(data=self.max_length_data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('first_name', serializer.errors)
        self.assertIn('last_name', serializer.errors)
        self.assertEqual(serializer.errors['first_name'][0], 'Ensure this field has no more than 30 characters.')
        self.assertEqual(serializer.errors['last_name'][0], 'Ensure this field has no more than 30 characters.')

class LoginSerializerTests(TestCase):
    def setUp(self):
        self.user_data = {
            'email': 'test@example.com',
            'password': 'Test@1234'
        }
        self.user = get_user_model().objects.create_user(**self.user_data)
        self.invalid_credentials = {
            'email': 'test@example.com',
            'password': 'Wrong@1234'
        }
        self.inactive_user_data = {
            'email': 'inactive@example.com',
            'password': 'Test@1234'
        }
        self.inactive_user = get_user_model().objects.create_user(
            email='inactive@example.com',
            password='Test@1234',
            is_active=False
        )
        self.empty_credentials = {
            'email': '',
            'password': ''
        }

    def test_valid_login(self):
        """SERIALIZER_010: Test login with valid credentials."""
        serializer = LoginSerializer(data=self.user_data)
        self.assertTrue(serializer.is_valid())
        user = serializer.validated_data
        self.assertEqual(user, self.user)

    def test_invalid_credentials(self):
        """SERIALIZER_011: Test login with invalid credentials."""
        serializer = LoginSerializer(data=self.invalid_credentials)
        self.assertFalse(serializer.is_valid())
        self.assertEqual(serializer.errors['non_field_errors'][0], 'Invalid credentials')

    def test_inactive_user(self):
        """SERIALIZER_012: Test login with inactive user."""
        serializer = LoginSerializer(data=self.inactive_user_data)
        self.assertFalse(serializer.is_valid())
        self.assertEqual(serializer.errors['non_field_errors'][0], 'Invalid credentials')

    def test_empty_credentials(self):
        """SERIALIZER_013: Test login with empty credentials."""
        serializer = LoginSerializer(data=self.empty_credentials)
        self.assertFalse(serializer.is_valid())
        self.assertIn('email', serializer.errors)
        self.assertIn('password', serializer.errors)
        self.assertEqual(serializer.errors['email'][0], 'This field may not be blank.')
        self.assertEqual(serializer.errors['password'][0], 'This field may not be blank.')

class AuthenticationViewsTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.user_data = {
            'email': 'test@example.com',
            'first_name': 'John',
            'last_name': 'Doe',
            'password': 'Test@1234',
            'password2': 'Test@1234'
        }
        self.login_data = {
            'email': 'test@example.com',
            'password': 'Test@1234'
        }
        self.user = get_user_model().objects.create_user(
            email=self.user_data['email'],
            password=self.user_data['password'],
            first_name=self.user_data['first_name'],
            last_name=self.user_data['last_name']
        )
        self.other_user = get_user_model().objects.create_user(
            email='other@example.com',
            password='Test@1234',
            first_name='Jane',
            last_name='Smith'
        )
        self.missing_field_data = {
            'email': 'newuser@example.com',
            'password': 'Test@1234'
            # Missing password2, first_name, last_name
        }

    def test_register_view_valid(self):
        """VIEW_001: Test user registration endpoint with valid data."""
        response = self.client.post('/api/auth/register/', {
            'email': 'newuser@example.com',
            'first_name': 'Jane',
            'last_name': 'Doe',
            'password': 'Test@1234',
            'password2': 'Test@1234'
        })
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['user']['email'], 'newuser@example.com')
        self.assertEqual(response.data['message'], 'User registered successfully')

    def test_register_view_invalid_data(self):
        """VIEW_002: Test registration with invalid data."""
        response = self.client.post('/api/auth/register/', {
            'email': 'invalid-email',
            'first_name': 'Jane',
            'last_name': 'Doe',
            'password': 'Test@1234',
            'password2': 'Test@1234'
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)

    def test_register_view_missing_fields(self):
        """VIEW_003: Test registration with missing fields."""
        response = self.client.post('/api/auth/register/', self.missing_field_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('password2', response.data)

    def test_login_view_valid(self):
        """VIEW_004: Test login endpoint with valid credentials."""
        response = self.client.post('/api/auth/login/', self.login_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)
        self.assertEqual(response.data['user']['email'], self.user_data['email'])

    def test_login_view_invalid_credentials(self):
        """VIEW_005: Test login with invalid credentials."""
        response = self.client.post('/api/auth/login/', {
            'email': self.user_data['email'],
            'password': 'Wrong@1234'
        })
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data['non_field_errors'][0], 'Invalid credentials')

    def test_login_view_missing_fields(self):
        """VIEW_006: Test login with missing fields."""
        response = self.client.post('/api/auth/login/', {'email': self.user_data['email']})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('password', response.data)

    def test_logout_view_valid(self):
        """VIEW_007: Test logout endpoint with valid refresh token."""
        login_response = self.client.post('/api/auth/login/', self.login_data)
        refresh_token = login_response.data['refresh']
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {login_response.data["access"]}')
        response = self.client.post('/api/auth/logout/', {'refresh': refresh_token})
        self.assertEqual(response.status_code, status.HTTP_205_RESET_CONTENT)
        self.assertEqual(response.data['message'], 'Successfully logged out')

    def test_logout_view_invalid_token(self):
        """VIEW_008: Test logout with invalid refresh token."""
        login_response = self.client.post('/api/auth/login/', self.login_data)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {login_response.data["access"]}')
        response = self.client.post('/api/auth/logout/', {'refresh': 'invalid_token'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_logout_view_no_token(self):
        """VIEW_009: Test logout without providing refresh token."""
        login_response = self.client.post('/api/auth/login/', self.login_data)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {login_response.data["access"]}')
        response = self.client.post('/api/auth/logout/', {})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_logout_view_multiple_attempts(self):
        """VIEW_010: Test logout with already blacklisted token."""
        login_response = self.client.post('/api/auth/login/', self.login_data)
        refresh_token = login_response.data['refresh']
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {login_response.data["access"]}')
        # First logout
        self.client.post('/api/auth/logout/', {'refresh': refresh_token})
        # Attempt second logout with same token
        response = self.client.post('/api/auth/logout/', {'refresh': refresh_token})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_profile_view_authenticated(self):
        """VIEW_011: Test profile endpoint with authenticated user."""
        login_response = self.client.post('/api/auth/login/', self.login_data)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {login_response.data["access"]}')
        response = self.client.get('/api/auth/profile/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], self.user_data['email'])

    def test_profile_view_unauthenticated(self):
        """VIEW_012: Test profile endpoint without authentication."""
        response = self.client.get('/api/auth/profile/')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_profile_view_wrong_user(self):
        """VIEW_013: Test profile endpoint with different authenticated user."""
        # Log in as other_user
        other_login_data = {'email': 'other@example.com', 'password': 'Test@1234'}
        login_response = self.client.post('/api/auth/login/', other_login_data)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {login_response.data["access"]}')
        response = self.client.get('/api/auth/profile/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], 'other@example.com')
        self.assertNotEqual(response.data['email'], self.user_data['email'])