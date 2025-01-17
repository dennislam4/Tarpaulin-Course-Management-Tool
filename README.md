Tarpaulin REST API

Tarpaulin is a REST API built using Flask that provides functionality for managing users, avatars, and courses. It includes authentication with Auth0, role-based access control, and integration with Google Cloud services.
Features

    User Management
        Add, retrieve, and update user information.
        Handle user avatars with Google Cloud Storage.
        Role-based access control for admins, instructors, and students.

    Course Management
        Create, update, and delete courses.
        Manage course enrollments for students.

    Authentication
        Secure endpoints with JWT authentication via Auth0.
        Role-based permissions for different user actions.

    Pagination
        Retrieve courses with limit and offset parameters for efficient navigation.

Technologies Used

    Backend: Flask
    Authentication: Auth0 with JWT
    Cloud Services: Google Cloud Datastore, Google Cloud Storage
    Database: Google Cloud Datastore
    Programming Language: Python

Endpoints
General

    GET / - Welcome message for the API.

User Endpoints

    GET /users - Get all users.
    GET /users/<id> - Retrieve a specific user's information.
    POST /users/login - Log in a user and retrieve a token.
    POST /users/<id>/avatar - Upload or update a user's avatar.
    GET /users/<id>/avatar - Retrieve a user's avatar.
    DELETE /users/<id>/avatar - Delete a user's avatar.

Course Endpoints

    POST /courses - Create a new course.
    GET /courses - Retrieve all courses with pagination.
    GET /courses/<id> - Retrieve a specific course's details.
    PUT /courses/<id> - Update a specific course's details.
    DELETE /courses/<id> - Delete a course.
    PUT /courses/<id>/students - Manage course enrollment.
    GET /courses/<id>/students - Retrieve students enrolled in a course.

Setup

    Clone the repository:

git clone https://github.com/yourusername/tarpaulin-api.git
cd tarpaulin-api

Install dependencies:

pip install -r requirements.txt

Set up environment variables: Create a .env file and add your Auth0 and Google Cloud credentials.

Run the application:

    python main.py

    Access the API: Visit http://127.0.0.1:8080/ in your browser or use a tool like Postman.

Error Codes

    401: Unauthorized ({'Error': 'Unauthorized'})
    403: Forbidden ({'Error': "You don't have permission on this resource"})
    400: Bad Request ({'Error': 'The request body is invalid'})
    404: Not Found ({'Error': 'Not found'})
