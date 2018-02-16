from flask import Flask, request, make_response, abort, jsonify, abort

from authenticators.authentication_required import authentication_required
from entity_repositories.entity_repository import EntityRepository
from policy_validators.policy_validator import PolicyValidator, ActionGrant
from settings import Config


app = Flask(__name__)


@app.route('/auth', methods=['GET'])
@authentication_required
def authorization_get():
    """Method to validate authorization for action"""
    action_id = request.args.get('action_id')
    audit_id = request.args.get('audit_id')
    action = request.args.get('action')
    project = request.args.get('project')

    if action_id is None:
        abort(400, description='action_id must be specified.')
    elif audit_id is None:
        abort(400, description='audit_id must be specified.')    
    elif action is None:
        abort(400, description='action must be specified.')
    elif project is None:
        abort(400, description='project must be specified.')

    serv_token = request.headers.get('X-Service-Token')
    subj_token = request.headers.get('X-Subject-Token')
    service = EntityRepository().gather_information(token=serv_token)
    subject = EntityRepository().gather_information(token=subj_token)

    


@app.route('/auth', methods=['POST'])
@authentication_required
def authorization_post():
    """Method to get authorization for action"""
    req_data = request.get_json()

    action = req_data.get('action')
    project = req_data.get('project')

    if action is None:
        abort(400, description='action must be specified')
    elif project is None:
        abort(400, description='project must be specified')

    serv_token = request.headers.get('X-Service-Token')
    subj_token = request.headers.get('X-Subject-Token')
    service = EntityRepository().gather_information(token=serv_token)
    subject = EntityRepository().gather_information(token=subj_token)

    result = PolicyValidator().create_authorization(action=action, project=project, subject=subject, service=service)

    if not result:
        abort(401, description='action not authorized.')

    return make_response(jsonify(result.to_public_dict()), 200)
