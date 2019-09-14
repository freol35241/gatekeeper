import jwt
import datetime

def create_token(dikt, expires_in, secret):
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
        secret,
        algorithm='HS256'
    )

def verify_token(request, cookie_name, secret):
    """
    Verify an existing JSON web token
    """
    auth_token = request.cookies.get(cookie_name, None)

    if not auth_token:
        # No token found
        return False

    try:
        payload = jwt.decode(auth_token, secret)
        #Token ok
        return payload

    except jwt.ExpiredSignatureError:
        # Token has expired, ask user to log in again
        return False

    except jwt.InvalidTokenError:
        # Invalid token! User must login!
        return False