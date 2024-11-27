"""
Main application file.

Author: Robin Shindelman
Date: 11/19/2024
"""

import google.cloud.storage
from flask import Flask, request, jsonify, url_for, send_file
from google.cloud import datastore, storage
import google.cloud
import io
import requests
import json
from os import getenv
import logging
from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv

from auth0_jwt import verify_jwt, AuthError

# CONSTANT STRINGS
USERS = 'users'
COURSES = 'courses'
AVATAR = 'avatar'
STUDENTS = 'students'
PROJ_BUCKET = 'shindelr_tarpaulin'
PROJ_ID = 'cs493-a6-shindelr'

ERR_MALFORMED_REQ = {"Error": "The request body is invalid"}  # 400
ERR_UNAUTHORIZED = {"Error": "Unauthorized"}  # 401
ERR_NOT_PERMITTED = {"Error": "You don't have permission on this resource"}  # 403
ERR_RESOURCE_NOT_FOUND = {"Error": "Not found"}  # 404
ERR_INVALID_ENROLLMENT = {"Error": "Enrollment data is invalid"}  # 409

# CONFIGURATION
app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

load_dotenv()
client = datastore.Client()

oauth = OAuth(app)
auth0 = oauth.register(
    'auth0',
    client_id=getenv('CLIENT_ID'),
    client_secret=getenv('CLIENT_SECRET'),
    api_base_url="https://" + getenv('DOMAIN'),
    access_token_url="https://" + getenv('DOMAIN') + "/oauth/token",
    authorize_url="https://" + getenv('DOMAIN') + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)

def verify_user(request: requests.Request, user_id: int):
    """
    Verify the user's JWT against the subs in datastore.

    Returns:
        payload: Decoded JWT payload for authenticated user on success
        1: `int` on Failure.
    """
    try:
        payload = verify_jwt(request)
        query = client.query(kind=USERS)
        query.add_filter('sub', '=', payload['sub'])
        user = list(query.fetch())
        # Failure if there is no user by that ID or the sub and ID do not match
        if len(user) < 1 or user[0].id != user_id:
            return 1
        return payload

    except AuthError as e:
        logging.warning(e)
        raise e  # Propogate the error up the chain.

def verify_admin_by_request(request: requests.Request):
    """
    Verify the user's JWT against admin subs.
    """
    try:
        payload = verify_jwt(request)
        query = client.query(kind=USERS)
        query.add_filter('role', '=', 'admin')
        query.add_filter('sub', '=', payload['sub'])
        user = list(query.fetch())
        if len(user) < 1:
            return 1
        return payload

    except AuthError as e:
        logging.warning(e)
        raise e  # Propogate the error up the chain.

def verify_instructor_by_request(request: requests.Request):
    """
    Verify the user's JWT against admin subs.
    """
    try:
        payload = verify_jwt(request)
        query = client.query(kind=USERS)
        query.add_filter('role', '=', 'instructor')
        query.add_filter('sub', '=', payload['sub'])
        user = list(query.fetch())
        if len(user) < 1:
            return 1
        return payload

    except AuthError as e:
        logging.warning(e)
        raise e  # Propogate the error up the chain.

def verify_instructor_by_id(id: int):
    """
    Verify the user's JWT against admin subs.
    """
    user = client.get(client.key(USERS, id))
    print(user)
    if user['role'] != 'instructor':
        return 1
    return 0

@app.route('/', methods=['GET'])
def root():
    """Root of app."""
    return "Please login to access Tarpaulin."

@app.route(f'/{USERS}', methods=['GET'])
def get_all_users():
    """
    Get all users in Tarpaulin.

    Header:
        JWT Bearer Token authenticating the user. Protected endpoint, Admin
        only.

    Response Statuses:
        200: OK
        401: The JWT is missing or invalid
        403: The JWT is valid but doesn’t belong to an admin. 
    """
    try:
        payload = verify_jwt(request)

        query_1 = client.query(kind=USERS)
        # Filter out everyone who's not an admin
        query_1.add_filter('role', '=', 'admin')
        query_1.add_filter('sub', '=', payload['sub'])
        admins = list(query_1.fetch())
        if len(admins) < 1:
            return ERR_NOT_PERMITTED, 403
        
        query_2 = client.query(kind=USERS)
        users = list(query_2.fetch())
        formatted_users = []

        # Don't allow users to see avatar or course information
        for user in users:
            user['id'] = user.key.id
            formatted_users.append(
                {
                    'id':   user['id'],
                    'role': user['role'],
                    'sub':  user['sub']
                }
            )
        
        return formatted_users, 200

    except AuthError as e:
        logging.warning("Invalid JWT for this resource", e)
        print(e.args[0])
        if e.args[0]['code'] == 'invalid_header':
            return ERR_UNAUTHORIZED, 401 

@app.route(f'/{USERS}/<int:user_id>', methods=['GET'])
def get_a_user(user_id:int):
    """
    Get a specific Tarpaulin user. 
    Protected endpoint, available to admin and the user the user id belongs to.

    Header:
        JWT Bearer Token authenticating admin or specific user.

    Required Path Parameters:
        user_id: `int` ID of the specific user to be queried.

    Response Statuses:
        200 OK.
        401 Failure. JWT is missing or invalid.
        403 Failure. JWT is valid, but the user doesn't exist. OR, JWT is 
            valid but does not belong to admin or specific user.

    Notes:
        - Response should always include 'id', 'role', 'sub'
        - Include 'avatar_url' if user has one.
        - If instructor or student, must include "courses[]"
        - If instructor: array contains links to courses being taught
        - If student: array contains links to courses being taken
    """
    try:
        # Verify user or admin against datastore and sub
        payload = verify_user(request, user_id)
        if payload == 1:
            return ERR_NOT_PERMITTED, 403

        # Shouldn't need to check this because already verified
        user = client.get(client.key(USERS, user_id))
        user['id'] = user.key.id
        if not user['avatar_url']:
            user.pop('avatar_url')
        user.pop('avatar_filename')  # Never include filename

        return user, 200

    except AuthError as e:
        logging.warning("Invalid JWT for this resource", e)
        print(e.args[0])
        if e.args[0]['code'] == 'invalid_header':
            return ERR_UNAUTHORIZED, 401

@app.route(f'/{USERS}/<int:user_id>/{AVATAR}', methods=['POST'])
def create_update_avatar(user_id: int):
    """
    Upload the .png in the request as the avatar of the user's avatar. If there
    is already an avatar for the user, it gets updated with the new file. The
    file is uploaded to Google Cloud Storage.
    
    Protections:
        JWT Bearer in the Authorization header. This endpoint is only available
        to users who match the JWT sub value in datastore.

    Required Path Parameters:
        user_id: `int` ID of specific user

    Responses:
        200: OK.
        400: Request does not include key 'file'. 
        401: Invalid JWT
        403: JWT and user_id mismatch
    """
    if 'file' not in request.files:
        return ERR_MALFORMED_REQ, 400

    try:
        payload = verify_user(request, user_id)
        if payload == 1:
            return ERR_NOT_PERMITTED, 403

        # Upload the file blog to Google Cloud Storage
        file_obj = request.files['file']
        storage_client = storage.Client()
        bucket = storage_client.get_bucket(PROJ_BUCKET)
        blob = bucket.blob(file_obj.filename)
        file_obj.seek(0)
        blob.upload_from_file(file_obj)

        # Store url in datastore
        avatar_url = url_for('get_user_avatar', user_id=user_id, _external=True)
        user = client.get(client.key(USERS, user_id))
        # User is verified already, so just update.
        user.update({
            'avatar_url': avatar_url,
            'avatar_filename': file_obj.filename
            })
        client.put(user)

        return {"avatar_url":avatar_url}, 200
    
    except AuthError as e:
        logging.warning('Authorization error in create-avatar')
        return ERR_UNAUTHORIZED, 401

@app.route(f'/{USERS}/<int:user_id>/{AVATAR}', methods=['GET'])
def get_user_avatar(user_id:int):
    """
    Get the avatar associated with the given user ID.

    Protections:
        A JWT Bearer token in the authorization header is required to access
        this endpoint. The 'sub' value in the JWT's payload must match up
        with the user ID in the path parameter.

    Path Parameters:
        user_id: `int` Required. The ID of the user being queried.

    Responses:
        200 Success
        401 Failure. Invalid JWT
        403 Failure. Valid JWT, does not belong to user
        404 Failure. The JWT/user combo is valid, but user does not have an
            avatar
    """
    try:
        payload = verify_user(request, user_id)
        if payload == 1:
            return ERR_NOT_PERMITTED, 403

        user = client.get(client.key(USERS, user_id))
        storage_client = storage.Client()
        bucket = storage_client.get_bucket(PROJ_BUCKET)

        if user['avatar_filename']:
            blob = bucket.blob(user['avatar_filename'])
        else:
            logging.warning("Tried to access non-existent avatar", 404)
            return ERR_RESOURCE_NOT_FOUND, 404

        file_obj = io.BytesIO()
        blob.download_to_file(file_obj)
        file_obj.seek(0)

        return send_file(file_obj, mimetype='image/x-png', download_name=user['avatar_url']), 200
    
    except AuthError as e:
        logging.warning("Auth error getting the user's avatar.")
        return ERR_UNAUTHORIZED, 401

@app.route(f'/{USERS}/<int:user_id>/{AVATAR}', methods=['DELETE'])
def delete_user_avatar(user_id:int):
    """
    Delete the avatar file stored in Google Cloud Storage bucket associated
    with the provided user ID.

    Protection:
        A JWT Bearer Token must be provided in the Authorization header of the
        request. The 'sub' value in the JWT payload must match the user's 
        stored record.

    Path Parameters:
        user_id: `int` Required. ID of the user

    Responses:
        204 Success
        401 Failure. Invalid JWT
        403 Failure. Valid JWT, does not belong to user
        404 Failure. The JWT/user combo is valid, but user does not have an
            avatar   
    """
    try:
        payload = verify_user(request, user_id)
        if payload == 1:
            return ERR_NOT_PERMITTED, 403
        
        try:
            # Retrieve and delete avatar info from datastore
            user = client.get(client.key(USERS, user_id))
            filename = user['avatar_filename']

            user.update({
                'avatar_url': '',
                'avatar_filename': ''
            })
            client.put(user)

            # Delete avatar from Cloud Storage
            storage_client = storage.Client()
            bucket = storage_client.get_bucket(PROJ_BUCKET)
            blob = bucket.blob(filename)
            blob.delete()

            return '', 204

        except ValueError as e:
            logging.warning("Tried to delete an avatar which does not exist", e)
            return ERR_RESOURCE_NOT_FOUND, 404

    except AuthError as e:
        logging.warning("Authorization error while deleting user avatar", e)
        return ERR_UNAUTHORIZED, 401

@app.route(f'/{COURSES}', methods=['POST'])
def create_a_course():
    """
    Create a course.

    Protections:
        A JWT Bearer Token must be provided in the Authorization header of the
        request. The JWT 'sub' value must correspond to an admin in the DB.
    
    Request Body Attributes:
    (ALL ARE REQUIRED)
        subject:        `String`   Subject code
        number:         `Integer`  Course number
        title:          `String`   Course title
        term:           `String`   Term offered
        instructor_id:  `Integer`  The instructor assigned to teach the course
    
    Responses:
    (401/403 take precedence over 400)
        201 Success
        400 Failure.
            Causes: Malformed request body, cannot be missing any of the attrs
            listed above. instructor_id does not match an existing instructor
            in the database.
        401 Failure. Invalid JWT
        403 Failure. JWT valid but not admin.
    """
    try:
        payload = verify_admin_by_request(request)
        if payload == 1:
            return ERR_NOT_PERMITTED, 403
        
        content = request.get_json()
        new_course = datastore.Entity(key=client.key(COURSES))

        try:
            # Check on existing instructor
            payload_2 = verify_instructor_by_id(content['instructor_id'])
            if payload_2 == 1:
                raise KeyError

            new_course.update({
                'subject':       content['subject'],
                'number':        content['number'],
                'title':         content['title'],
                'term':          content['term'],
                'instructor_id': content['instructor_id']
            })
            client.put(new_course)
            new_course['id'] = new_course.key.id
            new_course['self'] = url_for('get_a_course', course_id=new_course['id'], _external=True)

            # Update the instructor to have this course now
            instructor = client.get(client.key(USERS, content['instructor_id']))
            if not instructor:
                return ERR_MALFORMED_REQ, 400
            teaching_courses = instructor.pop('courses')
            if not teaching_courses:
                teaching_courses = list()
            if new_course['id'] not in teaching_courses:  # Avoid duplicates
                teaching_courses.append(new_course['id'])
                instructor.update({'courses': teaching_courses})
                client.put(instructor)

        except KeyError as e:
            logging.warning("Key Error while creating a course. Check body.", e)
            return ERR_MALFORMED_REQ, 400

        # Made it through succesfully
        return new_course, 201

    except AuthError as e:
        logging.warning("Auth error while creating a course.", e)
        return ERR_UNAUTHORIZED, 401
    
@app.route(f'/{COURSES}', methods=['GET'])
def get_all_courses():
    """
    Get a paginated list of all stored courses. Pages are of size 3, and sorted
    by subject.

    Protections:
        Unprotected endpoint. Have at it

    Query Parameters:
        **Note -- a request needs to have either both parameters or neither.
        offset: `int` How far to offset the pagination?
        limit: `int` Defaults to 3

    Responses:
        200 Success.
    """
    result_json = {}
    offset = request.args.get('offset', default=0, type=int)
    limit = request.args.get('limit', default=3, type=int)

    # Fetch paginated results ordered by their subject
    query = client.query(kind=COURSES)
    query.order = ['subject']
    query_iterator = query.fetch(limit=limit, offset=offset)
    pages = query_iterator.pages
    results = list(next(pages))

    for result in results:
        result['id'] = result.key.id
        result['self'] = url_for('get_a_course', course_id=result['id'], _external=True)
    result_json['courses'] = results

    # Add a next page if there are more than 3 results left to display
    if len(results) >= 3:
        next_page = url_for('get_all_courses', offset=(offset+limit), limit=limit, _external=True)
        result_json['next'] = next_page

    return result_json, 200

@app.route(f'/{COURSES}/<int:course_id>', methods=['GET'])
def get_a_course(course_id: int):
    """
    Retrieve an existing course.

    Protections:
        Unprotected endpoint. Have at it
    
    Path Paremeters:
        course_id: `int` ID of course to be found

    Responses:
        200 Success
        404 Failure. No course with this ID exists.
    
    """
    course = client.get(client.key(COURSES, course_id))
    if course:
        course['id'] = course.key.id
        course['self'] = url_for('get_a_course', course_id=course['id'], _external=True)
        return course, 200
    return ERR_RESOURCE_NOT_FOUND, 404

@app.route(f'/{COURSES}/<int:course_id>', methods=['PATCH'])
def update_a_course(course_id: int):
    """
    Perform a partial update on the course specified. Only properties specified
    in the request body will be updated.

    Protections:
        A JWT Bearer Token must be provided in the Authorization header of the
        request. The JWT 'sub' value must correspond to an admin in the DB.
    
    Path Parameters:
        course_id: `int` ID of course to be found
    
    Request Parameters:
    (ALL OPTIONAL)
        subject:        `String`   Subject code
        number:         `Integer`  Course number
        title:          `String`   Course title
        term:           `String`   Term offered
        instructor_id:  `Integer`  The instructor assigned to teach the course
    
    Responses:
    (401/403 take precedence over 400)
        201 Success
        400 Failure.
            Causes: Malformed request body, cannot be missing any of the attrs
            listed above. instructor_id does not match an existing instructor
            in the database.
        401 Failure. Invalid JWT
        403 Failure. JWT valid but not admin. OR JWT valid and admin, but no
            course exists by this ID    
    """
    try:
        payload = verify_admin_by_request(request)
        if payload == 1:
            return ERR_NOT_PERMITTED, 403

        # Get course in question
        content = request.get_json()
        course = client.get(client.key(COURSES, course_id))
        
        # Check on existing instructor, OK if instructor doesn't exist, NOT OK
        # if instructor exists and is invalid. If the instructor is good, update
        # their courses to include this course.
        try:
            instructor = client.get(client.key(USERS, content['instructor_id']))
            if not instructor:
                return ERR_MALFORMED_REQ, 400

            teaching_courses = instructor.pop('courses')
            if not teaching_courses:
                teaching_courses = list()
            if course_id not in teaching_courses:  # Avoid duplicates
                teaching_courses.append(course_id)
                instructor.update({'courses': teaching_courses})
                client.put(instructor)
        except KeyError as e:
            logging.warning("No instructor ID provided in course update", e)
            
        if course:
            # API assures that there will never be extraneous request attrs
            for item in content:
                course.update({f"{item}":content[f'{item}']})
            client.put(course)
            course['id'] = course.key.id
            course['self'] = url_for('get_a_course', course_id=course['id'], _external=True)

            # See if any other instructors are teaching the course, if so, remove
            instructor_query = client.query(kind=USERS)
            instructor_query.add_filter('courses', '=', course_id)
            instructor_query.add_filter('role', '=', 'instructor')
            instructors = list(instructor_query.fetch())
            for instructor in instructors:
                if instructor.key.id != course['instructor_id']:
                    print(f"Popping id: {instructor.key.id}")
                    print(f"Course instructor id: {course['instructor_id']}")
                    teaching_courses = instructor.pop('courses')
                    if not teaching_courses:
                        teaching_courses = list()
                    if course_id in teaching_courses:  # Remove other instructors
                        teaching_courses.remove(course_id)
                        instructor.update({'courses': teaching_courses})
                        client.put(instructor)

            return course, 201

        return ERR_NOT_PERMITTED, 403

    except AuthError as e:
        logging.warning("Auth Error while updating a course", e)
        return ERR_UNAUTHORIZED, 401

@app.route(f'/{COURSES}/<int:course_id>', methods=['DELETE'])
def delete_a_course(course_id: int):
    """
    Delete a course. 
    NOTE: Deletes enrollment of all students who were taking the course. Removes
        instructor association. 

    Protections:
        A JWT Bearer Token must be provided in the Authorization header of the
        request. The JWT 'sub' value must correspond to an admin in the DB.
    
    Path Parameters:
        course_id: `int` ID of course to be found

    Responses:
        200 Success
        401 Failure. JWT invalid
        403 Failure. JWT valid but not admin. OR JWT valid and admin, but no
            course exists by this ID.
    """
    try:
        payload = verify_admin_by_request(request)
        if payload == 1:
            return ERR_NOT_PERMITTED, 403
    
        course = client.get(client.key(COURSES, course_id))
        if course:
            # Start by pruning the course ID out of everyone's enrollment
            enrollment_q = client.query(kind=USERS)
            enrollment_q.add_filter('courses', '=', course_id)
            users = list(enrollment_q.fetch())
            for user in users:
                user_courses = user.pop('courses')
                if not user_courses:
                    user_courses = list()
                user_courses.remove(course_id)
                user.update({'courses': user_courses})
                client.put(user)

            # Delete the course itself
            client.delete(course)
            return '', 204
    
        return ERR_NOT_PERMITTED, 403

    except AuthError as e:
        logging.warning("Auth Error while deleting a course", e)
        return ERR_UNAUTHORIZED, 401

@app.route(f'/{COURSES}/<int:course_id>/{STUDENTS}', methods=['PATCH'])
def update_course_enrollment(course_id: int):
    """
    Enroll or disenroll students from a course.

    Protections:
        A JWT Bearer Token must be provided in the Authorization header of the
        request. The JWT 'sub' value must correspond to either an admin or the
        specific course instructor in the DB.
    
    Path Parameters:
        course_id: `int` ID of course to be found

    Request Body Attributes:
    (ALL REQUIRED)
        add:    `int[]`     An array, possibly empty, containing student IDs 
                            for students to enroll in the course.
        remove: `int[]`     An array, possibly empty, containing student IDs 
                            for students to be removed from the course.

    Responses:
    (401/403 take precedence over 409)
        200 Success
        401 Failure. JWT invalid
        403 Failure. JWT valid, but course doesn't exist. JWT/course valid but
            not an admin or instructor.
        409 Failure. Enrollment data in body is malformed. Student IDs may only
            exist in either the add or the remove arrays, never both. All
            students in the array must exist.
    
    """
    try:
        # Must either be admin or instructor of the course
        admin_payload = verify_admin_by_request(request)
        instructor_payload = verify_instructor_by_request(request)
        if admin_payload == 1 and instructor_payload == 1:
            return ERR_NOT_PERMITTED, 403

        course = client.get(client.key(COURSES, course_id))

        if course:
            # Check if instructor is the actual course instructor
            if instructor_payload != 1:
                instructor_query = client.query(kind=USERS)
                instructor_query.add_filter('sub', '=', instructor_payload['sub'])
                instructor = list(instructor_query.fetch())
                print(instructor)
                print(course['instructor_id'])
                if instructor[0].key.id != course['instructor_id']:
                    return ERR_NOT_PERMITTED, 403
            content = request.get_json()
            add_list = content['add']
            remove_list = content['remove']

            # Check for student duplicates and db existence
            for student_id in add_list:
                if student_id in remove_list:
                    return ERR_INVALID_ENROLLMENT, 409
                db_user = client.get(client.key(USERS, student_id))
                if not db_user or db_user['role'] != 'student':
                    return ERR_INVALID_ENROLLMENT, 409
            for student_id in remove_list:
                db_user = client.get(client.key(USERS, student_id))
                if not db_user or db_user['role'] != 'student':
                    return ERR_INVALID_ENROLLMENT, 409

            # Validated, update datastore entity now
            for student_id in add_list:
                student = client.get(client.key(USERS, student_id))
                student_courses = student.pop('courses')
                if not student_courses:
                    student_courses = list()
                if course_id not in student_courses:
                    student_courses.append(course_id)
                    student.update({'courses': student_courses})
                    client.put(student)

            for student_id in remove_list:
                student = client.get(client.key(USERS, student_id))
                student_courses = student.pop('courses')
                if not student_courses:
                    student_courses = list()
                if course_id in student_courses:
                    student_courses.remove(course_id)
                    student.update({'courses': student_courses})
                    client.put(student)

            return '', 200
    
        return ERR_NOT_PERMITTED, 403

    except AuthError as e:
        logging.warning("Auth Error while deleting a course", e)
        return ERR_UNAUTHORIZED, 401

@app.route(f'/{COURSES}/<int:course_id>/{STUDENTS}', methods=['GET'])
def get_course_enrollment(course_id: int):
    """
    Get a list of all students enrolled in a course.

    Protections:
        A JWT Bearer Token must be provided in the Authorization header of the
        request. The JWT 'sub' value must correspond to either an admin or the
        specific course instructor in the DB.
    
    Path Parameters:
        course_id: `int` ID of course to be found

    Responses:
        200 Success
        401 Failure. JWT invalid
        403 Failure. JWT valid, but course doesn't exist. JWT/course valid but
            not an admin or instructor.
    """
    try:
        # Must either be admin or instructor of the course
        admin_payload = verify_admin_by_request(request)
        instructor_payload = verify_instructor_by_request(request)
        if admin_payload == 1 and instructor_payload == 1:
            return ERR_NOT_PERMITTED, 403

        course = client.get(client.key(COURSES, course_id))
        if course:
            # Check if instructor is the actual course instructor
            if instructor_payload != 1:
                instructor_query = client.query(kind=USERS)
                instructor_query.add_filter('sub', '=', instructor_payload['sub'])
                instructor = list(instructor_query.fetch())
                if instructor[0].key.id != course['instructor_id']:
                    return ERR_NOT_PERMITTED, 403
            
            # Query for all students in the course
            student_query = client.query(kind=USERS)
            student_query.add_filter('courses', '=', course_id)
            student_query.add_filter('role', '=', 'student')
            students = list(student_query.fetch())
            student_ids = list()
            for student in students:
                student_ids.append(student.key.id)
            return student_ids, 200
    
        return ERR_UNAUTHORIZED, 403
    except AuthError as e:
        logging.warning("Auth Error while deleting a course", e)
        return ERR_UNAUTHORIZED, 401
    

# JWT ROUTES, FUNCTIONS, ERROR HANDLERS
@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload       

@app.route(f'/{USERS}/login', methods=['POST'])
def login_user():
    """
    Generate a JWT from the Auth0 domain and return it
    Request: JSON body with 2 properties with "username" and "password"
        of a user registered with this Auth0 domain
    Response: JSON with the JWT as the value of the property token 

    Statuses:
        200: OK.
        400: Malformed request body. Check password and username.
        401: Unauthorized password or username.   
    """
    content = request.get_json()
    try:
        username = content["username"]
        password = content["password"]
        body = {'grant_type':'password',
                'username':username,
                'password':password,
                'client_id':getenv('CLIENT_ID'),
                'client_secret':getenv('CLIENT_SECRET')
            }
        headers = { 'content-type': 'application/json' }
        url = 'https://' + getenv('DOMAIN') + '/oauth/token'
        r = requests.post(url, json=body, headers=headers)
        token = r.json()['id_token']
        token_response = {"token":token}
        return jsonify(token_response), 200
    
    except KeyError as e:
        logging.warning({"JWT Error": e})
        if e.args[0] == 'id_token':
            # JWT is invalid
            return ERR_UNAUTHORIZED, 401
        
        # Missing an attribute in the body
        return ERR_MALFORMED_REQ, 400


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
