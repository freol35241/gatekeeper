import os
import json
import bcrypt
import datetime
from flask import (Flask, current_app, request, render_template, 
                    redirect, make_response, jsonify, abort, url_for)
from playhouse.reflection import Introspector
from playhouse.flask_utils import FlaskDB

import utils

app = Flask(__name__)
app.secret_key = os.urandom(24)

### User defined variables
APP_NAME = os.environ.get('GATEKEEPER_APP_NAME', 'GATEKEEPER')

REDIRECT_URL_ON_FAIL = os.environ.get('GATEKEEPER_REDIRECT_URL')

if not REDIRECT_URL_ON_FAIL:
    raise ValueError('Provide a URL for redirects!')

COOKIE_NAME = os.environ.get('GATEKEEPER_COOKIE_NAME', 'GATEKEEPER')
COOKIE_DOMAIN = os.environ.get('GATEKEEPER_COOKIE_DOMAIN')

TOKEN_SECRET = os.environ.get('GATEKEEPER_TOKEN_SECRET', app.config.get('SECRET_KEY'))
TOKEN_EXPIRATION_TIME = os.environ.get('GATEKEEPER_COOKIE_EXPIRATION_TIME', 60*60*24) #Default to 24 hours

HEADER_KEY = os.environ.get('GATEKEEPER_HEADER_KEY', 'GATEKEEPER')

DB_URL = os.environ.get('GATEKEEPER_DB_URL')
DB_TABLE = os.environ.get('GATEKEEPER_DB_TABLE', 'USERS')

try:
    db_wrapper = FlaskDB(app, DB_URL)
    introspector = Introspector.from_database(db_wrapper.database)
    USER = introspector.generate_models(table_names=[DB_TABLE])[DB_TABLE]
except ValueError:
    raise ValueError('Provide a valid DB_URL!')


@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':
        # Extract request data
        username = request.form['username']
        password = request.form['pass']
        remember_me = request.form.get('remember-me') == 'on'

        next_page = request.args.get('next')
        if next_page is not None and not request.host in next_page:
            # Redirect is not on same domain (or any subdomain of) our current domain. Abort!
            abort(404)

        # Query database for username
        query = USER.select().where(USER.username == username)

        if not query.exists():
            # Send back to login page
            return redirect(url_for('login'))
        else:
            user = query.dicts().get()

        # Validate password
        hashed_pass = user.pop('password')    # Removing password from dict
        if not bcrypt.checkpw(password.encode(), hashed_pass.encode()):
            return redirect(url_for('login', next=next_page))      

        # Construct token
        expire_in = datetime.timedelta(seconds=TOKEN_EXPIRATION_TIME)

        auth_token = utils.create_token(
            {
                'id': user['id']
            },
            expire_in,
            TOKEN_SECRET
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

    result = utils.verify_token(request, COOKIE_NAME, TOKEN_SECRET)

    if result:
        # Verified, fetch user info
        user_id = result['id']
        query = USER.select().where(USER.id == user_id)
        
        if query.exists():
            # User found, construct json header

            user = query.dicts().get()

            auth_header = json.dumps(
                {
                    'username': user['username'],
                    'email': user['email'],
                }
            )

            # Set header on response
            resp = make_response(jsonify(success=True))
            resp.headers[HEADER_KEY] = auth_header

            return resp

    # Not valid, user must login, redirect to login url with correct next-page

    #Where to?
    print(request.headers, flush=True)
    host = request.headers.get('X-Forwarded-Host')
    uri = request.headers.get('X-Forwarded-Uri', '')

    return redirect(REDIRECT_URL_ON_FAIL+'?next=http://'+host+uri)


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



