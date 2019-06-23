import os
import jwt
import bcrypt
import datetime
from flask import (Flask, current_app, request, render_template, 
                    redirect, make_response, jsonify, abort, url_for)
from playhouse.reflection import Introspector
from playhouse.flask_utils import FlaskDB

app = Flask(__name__)
app.secret_key = b'f)\x03\x8brQX\x0e\xe9<k\x00G#gL'

### User defined variables
APP_NAME = os.environ.get('GATEKEEPER_APP_NAME', 'GATEKEEPER')
COOKIE_NAME = os.environ.get('GATEKEEPER_COOKIE_NAME', 'GATEKEEPER')
COOKIE_DOMAIN = os.environ.get('GATEKEEPER_COOKIE_DOMAIN', None)
TOKEN_SECRET = os.environ.get('GATEKEEPER_TOKEN_SECRET', app.config.get('SECRET_KEY'))
TOKEN_EXPIRATION_TIME = os.environ.get('GATEKEEPER_COOKIE_EXPIRATION_TIME', 60*60*24) #Default to 24 hours
DB_URL = os.environ.get('GATEKEEPER_DB_URL', None)
DB_TABLE = os.environ.get('GATEKEEPER_DB_TABLE', 'USERS')

try:
    db_wrapper = FlaskDB(app, DB_URL)
    introspector = Introspector.from_database(db_wrapper.database)
    USER = introspector.generate_models(table_names=[DB_TABLE])[DB_TABLE]
except ValueError:
    raise ValueError('Provide a valid DB_URL!')


def create_token(dikt, expires_in):
    """
    Create a JSON web token with dikt as extra payload
    """
    now = datetime.datetime.utcnow()

    mandatory_payload = {
        'exp': now + expires_in,
        'iat': now,
    }

    payload = {**dikt, **mandatory_payload}
    
    return jwt.encode(
        payload,
        TOKEN_SECRET,
        algorithm='HS256'
    )

@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':
        # Extract request data
        username = request.form['username']
        password = request.form['pass']
        remember_me = request.form.get('remember-me', None) == 'on'

        next_page = request.args.get('next')
        # TODO: next_page validation!

        # Query database for username
        query = USER.select().where(USER.username == username)

        if not query.exists():
            # Send back to login page
            return redirect(url_for('login'))
        else:
            user = query.dicts().get()

        # Validate password
        expected_pass = user.pop('password')    # Removing password from dict
        if not expected_pass == password:
            return redirect(url_for('login', next=next_page))

        # TODO: encrypted passwords!        

        # Construct token
        expire_in = datetime.timedelta(seconds=TOKEN_EXPIRATION_TIME)

        auth_token = create_token(
            {
                'username': user['username'],
                'email': user['email'],
                'id': user['id']
            },
            expire_in
        )

        # Return and set token inside cookie
        resp = redirect(next_page) if next_page is not None else make_response(jsonify(success=True))
        resp.set_cookie(COOKIE_NAME, 
                        auth_token.decode(), 
                        domain=COOKIE_DOMAIN, 
                        max_age=expire_in.total_seconds() if remember_me else None) # Set as a session cookie if remember_me is not checked

        return resp

    # Fetch next parameter from query
    action = url_for('login', next=request.args.get('next'))
    return render_template('login.html', APP_NAME=APP_NAME, ACTION=action)

@app.route('/verify')
def verify():

    auth_token = request.cookies.get(COOKIE_NAME, None)

    if auth_token:
        # We have a token of some sort, try decoding it
        try:
            payload = jwt.decode(auth_token, TOKEN_SECRET)
            #Token ok, return 200
            return jsonify(success=True)

        except jwt.ExpiredSignatureError:
            # Token has expired, ask user to log in again
            abort(401)

        except jwt.InvalidTokenError:
            # Invalid token! User must login!
            abort(401)

    # No token found. User must login!
    abort(401)

@app.route('/logout')
def logout():
    #Return response with empty cookie with expire time set to now
    resp = redirect(url_for('login'))
    resp.delete_cookie(COOKIE_NAME, domain=COOKIE_DOMAIN)

    return resp

@app.route('/recover')
def recover():
    ### TODO: Implement password recovery functionality
    abort(404)

@app.route('/account')
def account():
    ### TODO: Implement account management functionality
    abort(404)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=False)



