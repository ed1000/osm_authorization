import requests
from functools import wraps
from flask import g, request, redirect, url_for, make_response, abort
from settings import Config

def get_authorization_token():
    try:
        data = dict(
            method='password', 
            username=Config.AUTHENTICATION_USERNAME, 
            password=Config.AUTHENTICATION_PASSWORD)

        req = requests.post('http://' + Config.AUTHENTICATION_IP + '/auth', json=data)

        if req.status_code == 201: 
            Config.AUTHORIZATION_TOKEN = req.headers.get('X-Subject-Token')
    except Exception as ex:
        print(ex)

def verify_token(token):
    is_valid_token = False

    if Config.AUTHORIZATION_TOKEN is not None:
        headers = {
            'X-Service-Token': Config.AUTHORIZATION_TOKEN,
            'X-Subject-Token': Config.AUTHORIZATION_TOKEN,
        }

        req = requests.head('http://' + Config.AUTHENTICATION_IP + '/auth', headers=headers)

        is_valid_token = req.status_code == 200
    
    if is_valid_token is False:
        get_authorization_token()

        if Config.AUTHORIZATION_TOKEN is None:
            return None

    headers = {
        'content-type': 'application/json',
        'X-Service-Token': Config.AUTHORIZATION_TOKEN,
        'X-Subject-Token': token
    }

    req = requests.get('http://' + Config.AUTHENTICATION_IP + '/auth', headers=headers)

    data = dict(username=None, is_authenticated=False, is_service=False)

    if req.status_code == 200:
        req_json = req.json()
        data['username'] = req_json.get('username')
        data['is_authenticated'] = True
        data['is_service'] = 'service' in req_json.get('projects')

    return data

def authentication_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        serv_token = request.headers.get('X-Service-Token')
        subj_token = request.headers.get('X-Subject-Token')

        serv_user = verify_token(serv_token)
        if serv_user is None or serv_user.get('is_authenticated') is False:
            abort(403, description='service must be authenticated')
        elif serv_user.get('is_service') is False:
            abort(403, description='token provided as service is not service')

        subj_user = verify_token(subj_token)
        if subj_user is None or subj_user.get('is_authenticated') is False:
            abort(403, description='subject is not authenticated')
        
        return f(*args, **kwargs)
    return decorated_function



