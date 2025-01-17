import json
import requests
from flask import Flask, request, send_file, jsonify
from google.cloud import storage, datastore
from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth
import io

BUSINESS = "businesses"
ALGORITHMS = ["RS256"]
# ID and Secret hidden for security reasons
CLIENT_ID = '---'
CLIENT_SECRET = '---'
DOMAIN = 'dev-48mv8xvli2mrllsd.us.auth0.com'
PHOTO_BUCKET = 'lamden-hw6-photos'

ERROR_INVALID = {'Error': 'The request body is invalid'}
ERROR_UNAUTHORIZED = {'Error': 'Unauthorized'}
ERROR_PERMISSION = {'Error': "You don't have permission on this resource"}
ERROR_NOT_FOUND = {'Error': 'Not found'}

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'
oauth = OAuth(app)


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


def verify_jwt(request):
    if 'Authorization' not in request.headers:
        raise AuthError(ERROR_UNAUTHORIZED, 401)

    auth_header = request.headers['Authorization'].split()
    if len(auth_header) != 2 or auth_header[0].lower() != 'bearer':
        raise AuthError(ERROR_UNAUTHORIZED, 401)

    token = auth_header[1]
    print(f"Received token: {token}")  # Debug log

    try:
        jsonurl = urlopen(f"https://{DOMAIN}/.well-known/jwks.json")
        jwks = json.loads(jsonurl.read())
        unverified_header = jwt.get_unverified_header(token)
        rsa_key = next(
            {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
            for key in jwks["keys"] if key["kid"] == unverified_header["kid"]
        )

        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=ALGORITHMS,
            audience=CLIENT_ID,
            issuer=f"https://{DOMAIN}/"
        )
        print(f"Decoded payload: {payload}")  # Debug log
        return payload

    except (jwt.ExpiredSignatureError, jwt.JWTClaimsError, jwt.JWTError, StopIteration) as e:
        print(f"JWT error: {e}")  # Debug log
        raise AuthError(ERROR_UNAUTHORIZED, 401)
    except Exception as e:
        print(f"Unexpected error: {e}")  # Debug log
        raise AuthError(ERROR_UNAUTHORIZED, 401)


@app.route('/')
def index():
    return "Welcome to the Tarpaulin REST API!"


@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload


@app.route('/users/login', methods=['POST'])
def login():
    required_attributes = ["username", "password"]

    content = request.get_json()
    if not content or not all(attr in content for attr in required_attributes):
        return jsonify(ERROR_INVALID), 400

    try:
        username = content["username"]
        password = content["password"]

        body = {
            'grant_type': 'password',
            'username': username,
            'password': password,
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET
        }

        headers = {'content-type': 'application/json'}
        url = f'https://{DOMAIN}/oauth/token'

        r = requests.post(url, json=body, headers=headers)

        if r.status_code == 401:
            return jsonify(ERROR_UNAUTHORIZED), 401

        if r.status_code == 200:
            auth_response = r.json()
            response = {
                "token": auth_response.get("id_token")
            }
            return jsonify(response), 200

        return jsonify(ERROR_UNAUTHORIZED), 401

    except AuthError as e:
        return jsonify(e.error), e.status_code


# Get an array with all 9 users
@app.route('/users', methods=['GET'])
def get_users():
    try:
        verify_jwt(request)

        datastore_client = datastore.Client()
        query = datastore_client.query(kind='users')
        users = list(query.fetch())

        response = [{"id": user.key.id, "role": user.get("role"), "sub": user.get("sub")} for user in users]
        return jsonify(response), 200

    except AuthError as e:
        return jsonify(e.error), e.status_code
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return jsonify(ERROR_UNAUTHORIZED), 401


# Get a user and return user information
@app.route('/users/<id>', methods=['GET'])
def get_user(id):
    try:

        datastore_client = datastore.Client()
        key = datastore_client.key('users', int(id))
        user = datastore_client.get(key)

        if not user:
            return jsonify(ERROR_INVALID), 401

        app_domain = request.host_url.rstrip('/')

        user_info = {
            "id": user.id,
            "role": user.get("role"),
            "sub": user.get("sub")
        }

        storage_client = storage.Client()
        bucket = storage_client.get_bucket(PHOTO_BUCKET)
        blob = bucket.blob(str(user.id))
        if blob.exists():
            user_info["avatar_url"] = f"{app_domain}/users/{user.id}/avatar"

        if user.get("courses"):
            user_info["courses"] = [
                f"{app_domain}/courses/{course_id}"
                for course_id in user.get("courses", [])
            ]

        role = user.get("role")
        if role == "admin":
            user_info["courses"] = user.get("courses", [])
        elif role == "instructor":
            user_info["courses"] = user.get("courses", [])
        elif role == "student":
            user_info["courses"] = user.get("courses", [])

        return jsonify(user_info), 200

    except AuthError:
        return jsonify(ERROR_UNAUTHORIZED), 401


# Create/update a user's avatar
@app.route('/users/<id>/avatar', methods=['POST'])
def store_avatar(id):
    try:
        payload = verify_jwt(request)

        if payload is not True and (not isinstance(payload, dict) or payload.get('sub') != id):
            return ERROR_PERMISSION, 403

        if 'file' not in request.files:
            return ERROR_INVALID, 400

        file_obj = request.files['file']
        storage_client = storage.Client()
        bucket = storage_client.get_bucket(PHOTO_BUCKET)
        blob = bucket.blob(id)
        file_obj.seek(0)
        blob.upload_from_file(file_obj)
        app_domain = request.host_url.rstrip('/')


        avatar_url = f"{app_domain}/users/{id}/avatar"

        return jsonify({"avatar_url": avatar_url}), 200

    except AuthError:
        return ERROR_UNAUTHORIZED, 401


# Get a user's avatar
@app.route('/users/<id>/avatar', methods=['GET'])
def get_avatar(id):
    try:
        payload = verify_jwt(request)

        if payload is not True and (not isinstance(payload, dict) or payload.get('sub') != id):
            return ERROR_PERMISSION, 403

        storage_client = storage.Client()
        bucket = storage_client.get_bucket(PHOTO_BUCKET)
        blob = bucket.blob(id)

        if not blob.exists():
            return ERROR_NOT_FOUND, 404

        file_obj = io.BytesIO()
        blob.download_to_file(file_obj)
        file_obj.seek(0)
        return send_file(file_obj, mimetype='image/png', download_name=f"{id}.png")

    except AuthError:
        return ERROR_UNAUTHORIZED, 401


# Delete a user's avatar
@app.route('/users/<id>/avatar', methods=['DELETE'])
def delete_avatar(id):
    try:
        payload = verify_jwt(request)

        if payload is not True and (not isinstance(payload, dict) or payload.get('sub') != id):
            return ERROR_PERMISSION, 403

        storage_client = storage.Client()
        bucket = storage_client.get_bucket(PHOTO_BUCKET)
        blob = bucket.blob(id)

        if not blob.exists():
            return ERROR_NOT_FOUND, 404

        blob.delete()
        return '', 204

    except AuthError:
        return ERROR_UNAUTHORIZED, 401


# Create a course
@app.route('/courses', methods=['POST'])
def create_course():
    try:
        payload = verify_jwt(request)
        content = request.get_json()
        required_attributes = ['subject', 'number', 'title', 'term', 'instructor_id']

        if not content or not all(attr in content for attr in required_attributes):
            return ERROR_INVALID, 400

        datastore_client = datastore.Client()
        instructor_key = datastore_client.key('users', int(content['instructor_id']))
        instructor = datastore_client.get(instructor_key)

        if not instructor or instructor.get('role') != 'instructor':
            return ERROR_INVALID, 400

        new_course = datastore.Entity(key=datastore_client.key('courses'))
        new_course.update({
            'subject': content['subject'],
            'number': content['number'],
            'title': content['title'],
            'term': content['term'],
            'instructor_id': content['instructor_id']
        })
        datastore_client.put(new_course)

        response = {
            'id': new_course.key.id,
            'instructor_id': content['instructor_id'],
            'number': content['number'],
            'self': f'{request.host_url}courses/{new_course.key.id}',
            'subject': content['subject'],
            'term': content['term'],
            'title': content['title']
        }
        return jsonify(response), 201

    except AuthError:
        return ERROR_UNAUTHORIZED, 401


# Get all courses
@app.route('/courses', methods=['GET'])
def get_courses():
    datastore_client = datastore.Client()
    query = datastore_client.query(kind='courses')
    limit = int(request.args.get('limit', 3))  # Default limit is 3
    offset = int(request.args.get('offset', 0))

    query.order = ["subject"]
    courses_query = list(query.fetch(limit=limit, offset=offset))
    courses = []
    for course in courses_query:
        courses.append({
            "id": course.id,
            "instructor_id": course["instructor_id"],
            "number": course["number"],
            "self": f"{request.host_url.rstrip('/')}/courses/{course.id}",
            "subject": course["subject"],
            "term": course["term"],
            "title": course["title"]
        })

    total_count_query = datastore_client.query(kind='courses')
    total_count = len(list(total_count_query.fetch()))  # Get total count of courses

    next_offset = offset + limit
    next_url = None
    if len(courses_query) == limit and next_offset < total_count:
        next_url = f"{request.host_url.rstrip('/')}/courses?limit={limit}&offset={next_offset}"

    response = {
        "courses": courses,
        "next": next_url
    }

    return jsonify(response), 200


# Get a course
@app.route('/courses/<id>', methods=['GET'])
def get_course(id):
    try:

        datastore_client = datastore.Client()
        key = datastore_client.key('courses', int(id))

        course = datastore_client.get(key)
        if course is None:
            return ERROR_NOT_FOUND, 404

        response = {
            "id": course.id,
            "instructor_id": course["instructor_id"],
            "number": course["number"],
            "self": f'{request.host_url.rstrip("/")}/courses/{course.id}',
            "subject": course["subject"],
            "term": course["term"],
            "title": course["title"]
        }

        return jsonify(response), 200

    except ValueError:
        return ERROR_INVALID, 400


# Update a course
@app.route('/courses/<course_id>', methods=['PUT'])
def update_course(course_id):  # Match parameter name
    try:
        try:
            course_id = int(course_id)
        except ValueError:
            return {"Error": "The request body is invalid"}, 400

        datastore_client = datastore.Client()
        key = datastore_client.key('courses', course_id)
        course = datastore_client.get(key)

        if course is None:
            return ERROR_NOT_FOUND, 403

        if request.content_type != 'application/json':
            return ERROR_INVALID, 400

        content = request.get_json(silent=True)
        if not content:
            return ERROR_INVALID, 400

        required_keys = ["subject", "number", "title", "term", "instructor_id"]
        if not all(key in content for key in required_keys):
            return ERROR_INVALID, 400

        course.update({
            "subject": content["subject"],
            "number": content["number"],
            "title": content["title"],
            "term": content["term"],
            "instructor_id": content["instructor_id"],
        })

        datastore_client.put(course)
        response = {
            "id": course.key.id,
            "subject": course["subject"],
            "number": course["number"],
            "title": course["title"],
            "term": course["term"],
            "instructor_id": course["instructor_id"],
            "self": f"{request.host_url.rstrip('/')}/courses/{course.key.id}"
        }
        return jsonify(response), 200

    except Exception:
        return ERROR_INVALID, 400


# Delete a course
@app.route('/courses/<id>', methods=['DELETE'])
def delete_course(id):
    try:
        datastore_client = datastore.Client()
        key = datastore_client.key('courses', int(id))
        course = datastore_client.get(key)

        if course is None:
            return ERROR_NOT_FOUND, 404

        datastore_client.delete(key)
        return '', 204

    except AuthError:
        return ERROR_UNAUTHORIZED, 401


# Update enrollment in a course
@app.route('/courses/<id>/students', methods=['PUT'])
def update_course_enrollment(id):
    try:
        datastore_client = datastore.Client()
        course_key = datastore_client.key('courses', int(id))
        course = datastore_client.get(course_key)

        if course is None:
            return ERROR_NOT_FOUND, 404

        content = request.get_json()
        if not content or not isinstance(content.get("add", []), list) or not isinstance(content.get("remove", []), list):
            return ERROR_INVALID, 400

        enrolled_students = set(course.get('students', []))
        enrolled_students.update(content.get("add", []))
        enrolled_students.difference_update(content.get("remove", []))
        course['students'] = list(enrolled_students)
        datastore_client.put(course)

        response = {
            "course_id": course.key.id,
            "added_students": content.get("add", []),
            "removed_students": content.get("remove", []),
            "self": f"{request.host_url.rstrip('/')}/courses/{course.key.id}/students"
        }
        return jsonify(response), 200

    except AuthError:
        return ERROR_UNAUTHORIZED, 401
    except ValueError:
        return ERROR_INVALID, 400


# Get enrollment for a course
@app.route('/courses/<id>/students', methods=['GET'])
def get_enrollment(id):
    try:
        jwt_payload = verify_jwt(request)
        user_role = jwt_payload.get("role")
        user_sub = jwt_payload.get("sub")
        datastore_client = datastore.Client()
        key = datastore_client.key('courses', int(id))
        course = datastore_client.get(key)

        if course is None:
            return jsonify(ERROR_NOT_FOUND), 404

        course_instructor = course.get("instructor")
        if user_role != 'admin' and user_sub != course_instructor:
            return jsonify(ERROR_PERMISSION), 403

        students = course.get('students', [])
        student_ids = [student.id for student in students]

        return jsonify(student_ids), 200

    except AuthError:
        return jsonify(ERROR_UNAUTHORIZED), 401
    except Exception as e:
        return jsonify(ERROR_UNAUTHORIZED), 401


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
