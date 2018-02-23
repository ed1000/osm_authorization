from flask import Flask, request, make_response, abort, jsonify, abort

from authenticators.authentication_required import authentication_required, verify_token
from entity_repositories.entity_repository import EntityRepository
from policy_validators.policy_validator import PolicyValidator, ActionGrant
from settings import Config


app = Flask(__name__)


@app.route('/auth', methods=['GET'])
@authentication_required
def authorization_get():
    """Method to validate authorization for action"""
    
    action_id = request.args.get('action_id')
    action = request.args.get('action')
    operation = request.args.get('operation')
    project = request.args.get('project')
    ns_id = request.args.get('ns_id')

    if action_id is None:
        abort(400, description='action_id must be specified.')
    elif action is None:
        abort(400, description='action must be specified.')
    elif operation is None:
        abort(400, description='operation must be specified.')
    elif project is None:
        abort(400, description='project must be specified.')

    serv_info = verify_token(request.headers.get('X-Service-Token'))
    subj_info = verify_token(request.headers.get('X-Subject-Token'))

    if serv_info is None or subj_info is None:
        abort(500, description='could not authenticate authorization service')

    server_service = EntityRepository().gather_information(username=serv_info['username'])
    client_service = EntityRepository().gather_information(username=subj_info['username'])

    action_grant = PolicyValidator().verify_authorization(
        action_id=action_id,
        action=action,
        operation=operation,
        project=project,
        ns_id=ns_id,
        client_service=client_service,
        server_service=server_service)

    if action_grant is None:
        abort(401, 'Action/Operation not authorized')
    
    return make_response(jsonify(action_grant), 200)

@app.route('/auth', methods=['POST'])
@authentication_required
def authorization_post():
    """Method to get authorization for action"""
    req_data = request.get_json()

    action = req_data.get('action')
    project = req_data.get('project')
    ns_id = req_data.get('ns_id')

    if action is None:
        abort(400, description='action must be specified')
    elif project is None:
        abort(400, description='project must be specified')

    serv_info = verify_token(request.headers.get('X-Service-Token'))
    subj_info = verify_token(request.headers.get('X-Subject-Token'))

    if serv_info is None or subj_info is None:
        abort(500, description='could not authenticate authorization service')

    service = EntityRepository().gather_information(username=serv_info['username'])
    subject = EntityRepository().gather_information(username=subj_info['username'])

    action_grant = PolicyValidator().create_authorization(
        action=action, 
        project=project,
        ns_id=ns_id, 
        subject=subject, 
        service=service
    )

    if action_grant is None:
        abort(401, description='action not authorized.')

    return make_response(jsonify(action_grant), 200)
