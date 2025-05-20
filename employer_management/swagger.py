from drf_yasg import openapi
from drf_yasg.views import get_schema_view
from rest_framework import permissions

# Define the schema view for Swagger/OpenAPI documentation
schema_view = get_schema_view(
    openapi.Info(
        title="Employer Management API",
        default_version="v1",
        description="""
        The Employer Management API provides a robust system for user authentication and employer profile management. It supports user registration, login, logout, profile retrieval, and CRUD operations for employer profiles. The API uses JSON Web Tokens (JWT) for secure authentication and role-based access control. It is designed for users to register, authenticate, and manage employer profiles associated with their accounts.

        **Key Features:**
        - **User Registration:** Users register with an email, password, and optional first/last names. Passwords must meet complexity requirements (8+ characters, including uppercase, lowercase, digit, and special character). Disposable email domains are blocked.
        - **User Login:** Authenticates users with email and password, returning JWT access and refresh tokens.
        - **User Logout:** Blacklists refresh tokens to log out users securely.
        - **Profile Management:** Authenticated users can retrieve their profile details.
        - **Employer Management:** Authenticated users can create, list, retrieve, update, and delete employer profiles, with ownership-based access control.
        - **Phone Number Validation:** Employer phone numbers must be valid Bangladeshi mobile numbers (11 digits, starting with 0, and valid prefixes: 013, 014, 015, 016, 017, 018, 019).
        - **Email Validation:** Employer emails must be valid and unique per user, with disposable domains blocked.

        **Models Schema:**
        - **User:**
          - Fields: `id` (AutoField), `email` (unique, EmailField), `first_name` (CharField, max_length=30, nullable), `last_name` (CharField, max_length=30, nullable), `is_active` (Boolean, default=True), `is_staff` (Boolean, default=False), `date_joined` (DateTime, auto-set), `groups` (ManyToMany with auth.Group), `user_permissions` (ManyToMany with auth.Permission).
          - Authentication field: `email`.
        - **Employer:**
          - Fields: `id` (AutoField), `user` (ForeignKey to User), `company_name` (CharField, max_length=100), `contact_person_name` (CharField, max_length=100), `email` (EmailField), `phone_number` (CharField, max_length=14, validated for Bangladeshi format), `address` (TextField), `created_at` (DateTime, auto-set).
          - Constraint: Unique combination of `user` and `email`.

        **Relationships:**
        - A `User` can have multiple `Employer` profiles (one-to-many via `Employer.user`).
        - Each `Employer` profile is owned by a single `User`.

        **Output and Behavior:**
        - JSON responses for all endpoints.
        - Success responses include object data or success messages.
        - Error responses include messages and status codes (400, 401, 403, 404).
        - JWT authentication required for `/auth/logout/`, `/auth/profile/`, `/employers/employers/`, and `/employers/<int:pk>/`.

        **Authentication:**
        - Endpoints requiring authentication use JWT via `/auth/login/` or `/auth/register/`.
        - Use `Authorization: Bearer <access_token>` header.
        - Refresh tokens at `/auth/token/refresh/` (handled by `rest_framework_simplejwt`).
        - Access token lifetime: 60 minutes.
        - Refresh token lifetime: 1 day.
        - Refresh tokens are rotated and blacklisted after use or logout.

        **JSON Format for Creating Objects (POST):**
        - **User Registration:**
          - `/auth/register/`:
            ```json
            {
              "email": "user@example.com",
              "first_name": "John",
              "last_name": "Doe",
              "password": "SecurePass123!",
              "password2": "SecurePass123!"
            }
            ```
            - **Description**: Registers a new user with a unique email and password. The password must be at least 8 characters, including one uppercase letter, one lowercase letter, one digit, and one special character (`!@#$%^&*(),.?":{}|<>`). Disposable email domains (e.g., mailinator.com, tempmail.com, 10minutemail.com) are blocked. The `first_name` and `last_name` fields are optional (max 30 characters each). Returns user details, JWT access and refresh tokens, and a success message.
            - **Logged in as**: None (public endpoint).
            - **Outcome**: Creates a user with `is_active=True`, `is_staff=False`, and `date_joined` set to the current timestamp. Returns 400 if email is invalid, already registered, or disposable, or if passwords do not match or fail validation.
            - **Success Response (201 Created)**:
              ```json
              {
                "user": {
                  "id": 1,
                  "email": "user@example.com",
                  "first_name": "John",
                  "last_name": "Doe",
                  "date_joined": "2025-05-21T00:00:00Z"
                },
                "refresh": "<refresh_token>",
                "access": "<access_token>",
                "message": "User registered successfully"
              }
              ```
            - **Error Responses**:
              - **400 Bad Request**: 
                - `{ "email": "Invalid email format" }`
                - `{ "email": "Disposable email addresses are not allowed" }`
                - `{ "email": "Email is already registered" }`
                - `{ "password": "Password must contain at least one uppercase letter" }`
                - `{ "password": "Password must contain at least one lowercase letter" }`
                - `{ "password": "Password must contain at least one digit" }`
                - `{ "password": "Password must contain at least one special character" }`
                - `{ "password": "Passwords must match" }`
        - **User Login:**
          - `/auth/login/`:
            ```json
            {
              "email": "user@example.com",
              "password": "SecurePass123!"
            }
            ```
            - **Description**: Authenticates a user with email and password. Returns JWT access and refresh tokens and user details if credentials are valid and the user is active. Uses `django.contrib.auth.authenticate` for validation.
            - **Logged in as**: None (public endpoint).
            - **Outcome**: Returns 401 if credentials are invalid or the user is inactive.
            - **Success Response (200 OK)**:
              ```json
              {
                "refresh": "<refresh_token>",
                "access": "<access_token>",
                "user": {
                  "id": 1,
                  "email": "user@example.com",
                  "first_name": "John",
                  "last_name": "Doe",
                  "date_joined": "2025-05-21T00:00:00Z"
                }
              }
              ```
            - **Error Responses**:
              - **401 Unauthorized**: `{ "non_field_errors": "Invalid credentials" }`
        - **User Logout:**
          - `/auth/logout/`:
            ```json
            {
              "refresh": "<refresh_token>"
            }
            ```
            - **Description**: Blacklists the provided refresh token to log out the user. Requires a valid JWT access token in the `Authorization` header.
            - **Logged in as**: Authenticated user.
            - **Outcome**: Blacklists the refresh token and returns a success message. Returns 400 if the refresh token is missing or invalid.
            - **Success Response (205 Reset Content)**:
              ```json
              {
                "message": "Successfully logged out"
              }
              ```
            - **Error Responses**:
              - **400 Bad Request**: `{ "error": "Refresh token is required" }`
              - **400 Bad Request**: `{ "error": "<exception_message>" }`
              - **401 Unauthorized**: `{ "detail": "Authentication credentials were not provided." }`
        - **User Profile:**
          - `/auth/profile/` (GET):
            ```json
            {}
            ```
            - **Description**: Retrieves the authenticated user's profile details, including `id`, `email`, `first_name`, `last_name`, and `date_joined`. Requires a valid JWT access token in the `Authorization` header.
            - **Logged in as**: Authenticated user.
            - **Outcome**: Returns user details.
            - **Success Response (200 OK)**:
              ```json
              {
                "id": 1,
                "email": "user@example.com",
                "first_name": "John",
                "last_name": "Doe",
                "date_joined": "2025-05-21T00:00:00Z"
              }
              ```
            - **Error Responses**:
              - **401 Unauthorized**: `{ "detail": "Authentication credentials were not provided." }`
        - **Employer Creation:**
          - `/employers/employers/` (POST):
            ```json
            {
              "company_name": "Example Corp",
              "contact_person_name": "Jane Smith",
              "email": "contact@example.com",
              "phone_number": "01775289775",
              "address": "123 Business Road, Dhaka"
            }
            ```
            - **Description**: Creates a new employer profile for the authenticated user. The `company_name` and `contact_person_name` must be at least 2 characters and contain valid characters (alphanumeric, spaces, hyphens, or ampersands for company; alphanumeric, spaces, or hyphens for contact person). The `email` must be valid and not disposable (e.g., mailinator.com, tempmail.com, 10minutemail.com), and unique per user. The `phone_number` must be an 11-digit Bangladeshi mobile number starting with 0 and a valid prefix (013, 014, 015, 016, 017, 018, 019). The `address` must not be empty. The `user` field is automatically set to the authenticated user. Requires a valid JWT access token in the `Authorization` header.
            - **Logged in as**: Authenticated user.
            - **Outcome**: Creates an employer profile with `created_at` set to the current timestamp. Returns 400 if input is invalid or the email is already used by another employer for the same user.
            - **Success Response (201 Created)**:
              ```json
              {
                "id": 1,
                "company_name": "Example Corp",
                "contact_person_name": "Jane Smith",
                "email": "contact@example.com",
                "phone_number": "01775289775",
                "address": "123 Business Road, Dhaka",
                "created_at": "2025-05-21T00:00:00Z"
              }
              ```
            - **Error Responses**:
              - **400 Bad Request**: 
                - `{ "company_name": "Company name cannot be empty" }`
                - `{ "company_name": "Company name must be at least 2 characters long" }`
                - `{ "company_name": "Company name contains invalid characters" }`
                - `{ "contact_person_name": "Contact person name cannot be empty" }`
                - `{ "contact_person_name": "Contact person name must be at least 2 characters long" }`
                - `{ "contact_person_name": "Contact person name contains invalid characters" }`
                - `{ "email": "Invalid email format" }`
                - `{ "email": "Disposable email addresses are not allowed" }`
                - `{ "email": "This email is already in use by another employer for this user" }`
                - `{ "phone_number": "Phone number must be 11 digits starting with '0'" }`
                - `{ "phone_number": "Phone number must start with a valid Bangladeshi mobile prefix (013, 014, 015, 016, 017, 018, 019)" }`
                - `{ "address": "Address cannot be empty" }`
              - **401 Unauthorized**: `{ "detail": "Authentication credentials were not provided." }`
        - **Employer List:**
          - `/employers/employers/` (GET):
            ```json
            []
            ```
            - **Description**: Lists all employer profiles owned by the authenticated user. Returns an empty list if none exist. Requires a valid JWT access token in the `Authorization` header.
            - **Logged in as**: Authenticated user.
            - **Outcome**: Returns a list of employer profiles.
            - **Success Response (200 OK)**:
              ```json
              [
                {
                  "id": 1,
                  "company_name": "Example Corp",
                  "contact_person_name": "Jane Smith",
                  "email": "contact@example.com",
                  "phone_number": "01775289775",
                  "address": "123 Business Road, Dhaka",
                  "created_at": "2025-05-21T00:00:00Z"
                }
              ]
              ```
            - **Error Responses**:
              - **401 Unauthorized**: `{ "detail": "Authentication credentials were not provided." }`
        - **Employer Detail:**
          - `/employers/<int:pk>/` (GET):
            ```json
            {}
            ```
            - **Description**: Retrieves details of a specific employer profile by ID. The profile must be owned by the authenticated user. Requires a valid JWT access token in the `Authorization` header and the `IsEmployerOwner` permission.
            - **Logged in as**: Authenticated user (owner of the employer profile).
            - **Outcome**: Returns the employer profile details.
            - **Success Response (200 OK)**:
              ```json
              {
                "id": 1,
                "company_name": "Example Corp",
                "contact_person_name": "Jane Smith",
                "email": "contact@example.com",
                "phone_number": "01775289775",
                "address": "123 Business Road, Dhaka",
                "created_at": "2025-05-21T00:00:00Z"
              }
              ```
            - **Error Responses**:
              - **401 Unauthorized**: `{ "detail": "Authentication credentials were not provided." }`
              - **403 Forbidden**: `{ "detail": "You do not have permission to perform this action." }`
              - **404 Not Found**: `{ "detail": "Not found." }`
        - **Employer Update:**
          - `/employers/<int:pk>/` (PUT):
            ```json
            {
              "company_name": "Updated Corp",
              "contact_person_name": "Jane Doe",
              "email": "newcontact@example.com",
              "phone_number": "01775289776",
              "address": "456 Business Road, Dhaka"
            }
            ```
            - **Description**: Updates an existing employer profile by ID. The profile must be owned by the authenticated user. All fields are required and validated as in the creation endpoint. Requires a valid JWT access token in the `Authorization` header and the `IsEmployerOwner` permission.
            - **Logged in as**: Authenticated user (owner of the employer profile).
            - **Outcome**: Updates the employer profile and returns updated details. Returns 400 if input is invalid or the email is already used by another employer for the same user.
            - **Success Response (200 OK)**:
              ```json
              {
                "id": 1,
                "company_name": "Updated Corp",
                "contact_person_name": "Jane Doe",
                "email": "newcontact@example.com",
                "phone_number": "01775289776",
                "address": "456 Business Road, Dhaka",
                "created_at": "2025-05-21T00:00:00Z"
              }
              ```
            - **Error Responses**:
              - **400 Bad Request**: Same as Employer Creation errors.
              - **401 Unauthorized**: `{ "detail": "Authentication credentials were not provided." }`
              - **403 Forbidden**: `{ "detail": "You do not have permission to perform this action." }`
              - **404 Not Found**: `{ "detail": "Not found." }`
        - **Employer Delete:**
          - `/employers/<int:pk>/` (DELETE):
            ```json
            {}
            ```
            - **Description**: Deletes an existing employer profile by ID. The profile must be owned by the authenticated user. Requires a valid JWT access token in the `Authorization` header and the `IsEmployerOwner` permission.
            - **Logged in as**: Authenticated user (owner of the employer profile).
            - **Outcome**: Deletes the employer profile and returns no content.
            - **Success Response (204 No Content)**:
              ```json
              {}
              ```
            - **Error Responses**:
              - **401 Unauthorized**: `{ "detail": "Authentication credentials were not provided." }`
              - **403 Forbidden**: `{ "detail": "You do not have permission to perform this action." }`
              - **404 Not Found**: `{ "detail": "Not found." }`

        **Error Handling:**
        - **400 Bad Request**: Invalid input (e.g., missing fields, invalid email/phone, weak password, duplicate email).
        - **401 Unauthorized**: Missing or invalid JWT token.
        - **403 Forbidden**: Insufficient permissions (e.g., non-owner attempting to access/update/delete an employer profile).
        - **404 Not Found**: Resource not found (e.g., employer profile by ID).

        **Additional Notes:**
        - **Phone Numbers**: Must be 11 digits, starting with `0`, and use valid Bangladeshi mobile prefixes (013, 014, 015, 016, 017, 018, 019). Supports input with `+880` (converted to `0`).
        - **Passwords**: Must be 8+ characters, with at least one uppercase letter, one lowercase letter, one digit, and one special character (`!@#$%^&*(),.?":{}|<>`).
        - **Emails**: Validated with regex (`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`). Disposable domains (e.g., mailinator.com, tempmail.com, 10minutemail.com) are blocked.
        - **Permissions**: The `IsEmployerOwner` permission ensures only the owner of an employer profile can retrieve, update, or delete it.
        - **JWT Configuration**: Managed by `rest_framework_simplejwt`. Access tokens expire in 60 minutes, refresh tokens in 1 day, with rotation and blacklisting enabled.
        """,
        terms_of_service="https://www.example.com/terms/",
        contact=openapi.Contact(email="support@example.com"),
        license=openapi.License(name="MIT License"),
    ),
    public=True,
    permission_classes=[permissions.AllowAny],
)