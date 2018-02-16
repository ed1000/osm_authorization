import re, json

from settings import Config

class ActionGrant:
    def __init__(self, action_id, audit_id, action, project):
        self.action_id = action_id
        self.audit_id = audit_id
        self.action = action
        self.project = project
    
    def to_public_dict(self):
        data = dict()

        data['action_id'] = self.action_id
        data['audit_id'] = self.audit_id
        data['action'] = self.action
        data['project'] = self.project

        return data

class PolicyValidator:
    COMPILED_REGEX = re.compile(r'([ a-zA-Z0-9_]+)_[0-9]+')
    POLICIES = json.load(open(Config.AUTHORIZATION_POLICY_FILE))
    EXPIRATION_TIME = Config.REDIS_EXPIRATION_TIME
    USER_MARKER = Config.AUTHORIZATION_USER_MARKER
    ADMIN_MARKER = Config.AUTHORIZATION_ADMIN_MARKER
    SERVICE_MARKER = Config.AUTHORIZATION_SERVICE_MARKER

    def __init__(self):
        self.is_valid = self.validate_policy()

        if self.is_valid:
            self.redis_db = StrictRedis(host=settings.REDIS_URL, port=settings.REDIS_PORT)

    def validate_policy(self):
        # TODO: validate loaded file
        return True

    def verify_issuer_permissions(self, call_chain, issuer, is_in_project=False):
        markers = str.split(call_chain[0], '|')

        if len(markers) == 1:
            if PolicyValidator.USER_MARKER in markers:
                return not issuer.is_service and not issuer.is_admin and is_in_project
            elif PolicyValidator.SERVICE_MARKER in markers:
                return issuer.is_service
            elif PolicyValidator.ADMIN_MARKER in markers:
                return issuer.is_admin
        elif len(markers) == 2:
            if PolicyValidator.USER_MARKER in markers and \
                    PolicyValidator.ADMIN_MARKER in markers:
                return issuer.is_admin or is_in_project
            elif PolicyValidator.ADMIN_MARKER in markers and \
                    PolicyValidator.SERVICE_MARKER in markers:
                return issuer.is_admin or issuer.is_service

        return False

    def verify_component(self, call_chain, component, position):
        search = re.search(PolicyValidator.COMPILED_REGEX, component.username)

        if search:
            return call_chain[position] == search.group(1)
        return False

    def generate_action_id(self, action):
        action_id = hashlib.sha512(str.encode(action + str(time.time())))

        while self.redis_db.exists(action_id):
            action_id = hashlib.sha512(str.encode(action + str(time.time())))

        return action_id

    def verify_authorization(self, action, project, issuer, component, action_id=None):
        if not self.is_valid:
            raise PolicyFileError("Authorization policy file has an error...")

        call_chain = PolicyValidator.POLICIES.get(action)

        if not call_chain:
            return False

        if action_id is None:
            user_in_project = project in TokenValidator().get_project_list(issuer.token)

            user_permission = self.verify_issuer_permissions(call_chain, issuer, user_in_project)
            service_permission = self.verify_component(call_chain, component, 0)

            if user_permission and service_permission:
                action_id = self.generate_action_id(action=action)

                self.redis_db.rpush(action_id, issuer.username)
                self.redis_db.rpush(action_id, component.username)
                self.redis_db.expire(action_id, PolicyValidator.EXPIRATION_TIME)

                return True, action_id
        else:
            is_action_expired = self.redis_db.exists(action_id)

            if not is_action_expired:
                position = self.redis_db.llen(action_id)-1

                caller_component_permission = self.verify_component(call_chain, issuer, position)
                callee_component_permission = self.verify_component(call_chain, component, position + 1)
                caller_previous_authorization = self.redis_db.lindex(action_id, -1) == issuer.username

                if caller_component_permission and callee_component_permission and \
                        caller_previous_authorization:
                    self.redis_db.rpush(action_id, component.username)
                    self.redis_db.expire(action_id, PolicyValidator.EXPIRATION_TIME)
                    return True, action_id

        return False,

    
    def __init__(self):
        pass
    
    def create_authorization(self, action, project, subject, service):
        return ActionGrant(action_id=0, audit_id=0, action=action, project=project)

    def verify_authorization(self, action, project, client_service, server_service):
        return ActionGrant(action_id=0, audit_id=0, action=action, project=project)
