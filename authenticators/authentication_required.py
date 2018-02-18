from functools import wraps
from flask import g, request, redirect, url_for, make_response, abort

def verify_token(token):
    return (True, True)

def authentication_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        serv_token = request.headers.get('X-Service-Token')
        subj_token = request.headers.get('X-Subject-Token')

        serv_user = verify_token(serv_token)
        if serv_user is None or serv_user[0] is False:
            abort(403, description='service must be authenticated')
        elif serv_user[1] is False:
            abort(403, description='token provided as service is not service')

        subj_user = verify_token(subj_token)
        if subj_user is None or subj_user[0] is False:
            abort(403, description='subject is not authenticated')
        
        return f(*args, **kwargs)
    return decorated_function



