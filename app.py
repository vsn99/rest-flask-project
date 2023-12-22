from flask import Flask, request, jsonify
import mysql.connector
from jwt.exceptions import DecodeError
from functools import wraps
import os,requests,jwt,json,logging
from flask import make_response
import requests
from flask import Flask, jsonify, request, make_response
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
import mysql.connector
# import jwt
from functools import wraps
import json
import os
from jwt.exceptions import DecodeError

import logging
from flask import make_response

# Configuration for flask application.
app = Flask(__name__)

app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'  # Change this to a secure secret key
app.config['JWT_TOKEN_LOCATION'] = ['headers', 'cookies']
app.config['JWT_COOKIE_CSRF_PROTECT'] = False  # Disable CSRF protection for cookies
app.config['JWT_ACCESS_COOKIE_NAME'] = 'token'


# Creation of global cursor.
conn = mysql.connector.connect(
        host="database.clau0466sb6g.us-east-1.rds.amazonaws.com",
        user="admin",
        password="12345678",
        database="database1"
)
cursor = conn.cursor()

jwt = JWTManager(app)


# Create the table in the RDS if it does not exist.
cursor.execute("CREATE TABLE IF NOT EXISTS USER (username VARCHAR(50) UNIQUE NOT NULL,password VARCHAR(20),roles VARCHAR(20));")

conn.commit()



# User Registration
@app.route('/register', methods=['POST'])
def register():
    global cursor
    if not conn.is_connected():
        conn.reconnect()
    cursor = conn.cursor()
    try:
        data = request.get_json()
        print(data)
        username = data['username']
        print(username)
        password = data['password']
        print(password)
        roles = data['roles']  # Optional roles parameter
        print(roles)

        # Check if the username and email are available
        # cursor.execute(f"SELECT * FROM users WHERE email = {email}")
        qu = f"SELECT username FROM USER"
        cursor.execute(qu)
        existing_user = cursor.fetchall()
        if data['username'] in existing_user:
            return jsonify({'error': 'username already exists'}), 400
        print("after 1st cursor")

        # Register the user
        qu = "INSERT INTO USER (username, password, roles) VALUES (\"" + str(username) + "\",\"" + str(password) + "\",\"" + str(roles) + "\");"
        print(qu)
        cursor.execute(qu)
        # cursor.execute(f"INSERT INTO users_1 (email, password, roles) VALUES ({email}, {password}, {roles});")
        conn.commit()
        cursor.close()

        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500



# User Login
@app.route('/login', methods=['POST'])
def login():
    global cursor
    if not conn.is_connected():
        conn.reconnect()
        cursor = conn.cursor()
    try:
        data = request.get_json()
        username = data['username']
        password = data['password']

        
        # Authenticate the user
        cursor.execute("SELECT * FROM USER WHERE username = %s AND password = %s", (username, password))
        user = cursor.fetchone()

        if user:
            access_token = create_access_token(identity=username)
            response = make_response(jsonify({'message': 'Login successful'}))
            response.set_cookie('token', access_token)

            return response, 200
        else:
            return jsonify({'error': 'Invalid username or password'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Custom decorator for authorization.
def roles_required(*required_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            current_user = get_jwt_identity()
            cursor.execute("SELECT roles FROM USER WHERE username = %s", (current_user,))
            user_roles = cursor.fetchone()[0]

            if 'admin' in user_roles.split(','):
                # Admin has access to all functionalities
                return f(*args, **kwargs)
            elif any(role in user_roles.split(',') for role in required_roles):
                # User has access to the specified roles
                return f(*args, **kwargs)
            else:
                return jsonify({'error': 'Unauthorized: User does not have the necessary role'}), 403

        return decorated_function

    return decorator



@app.route('/add', methods=['POST'])
@jwt_required()
@roles_required('admin', 'user')
def get_add():
    try:
        current_user_id = get_jwt_identity()
        response = request.get_json()
        # if response.status_code != 200:
        #     return jsonify({'error': response.json()['message']}), response.status_code

        num1 = response.get('a')
        num2 = response.get('b')

        if num1 is None or num2 is None:
            return jsonify({'error': 'invalid no format'}), 400

        try:
            result = float(num1) + float(num2)
            return jsonify({'result': result})
        except ValueError:
            return jsonify({'error': 'invalid number format'}), 400

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Start flask application.
if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True)


# Shut down the connection.
# cursor.execute("Show tables;")
# print(cursor.fetchall())
conn.close()