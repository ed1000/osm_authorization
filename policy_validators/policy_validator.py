import re, json, pprint, redis, hashlib, time
from settings import Config

class ActionGrant:
    def __init__(self, action_id, action, project, subject, service, operations=[]):
        self.action_id = action_id
        self.action = action
        self.project = project
        self.subject = subject
        self.service = service
        self.operations = operations
    
    def to_public_dict(self):
        data = dict()

        data['action_id'] = self.action_id
        data['action'] = self.action
        data['project'] = self.project

        return data
    
    def to_redis_dict(self):
        data = dict()

        data['action_id'] = self.action_id
        data['action'] = self.action
        data['project'] = self.project
        data['subject'] = self.subject
        data['service'] = self.service
        data['operations'] = self.operations

        return data

def validate_policy(policy_file):
    top_keys = ['actions', 'operations', 'action_to_operations', 'action_policies']
    
    if policy_file is None:
        raise Exception('ERROR IN POLICY FILE: File missing')
    
    count = 0
    for key in policy_file.keys():
        if key in top_keys:
            count += 1
    
    if count != len(top_keys):
        raise Exception('ERROR IN POLICY FILE: Missing parameters')

    actions = []
    for action in policy_file['actions']:
        if action in actions:
            raise Exception('ERROR IN POLICY FILE: Duplicated actions')
        actions.append(action)

    operations = []
    for operation in policy_file['operations']:
        if operation in operations:
            raise Exception('ERROR IN POLICY FILE: Duplicated operations')
        operations.append(operation)
    
    actions = []
    for action_to_operations in policy_file['action_to_operations']:
        if action_to_operations['action_name'] not in policy_file['actions']:
            raise Exception('ERROR IN POLICY FILE: Action is not present in the actions list')
        elif action_to_operations['action_name'] in actions:
            raise Exception('ERROR IN POLICY FILE: Duplicated action in action_to_operations mapping')
        
        actions.append(action_to_operations['action_name'])

        operations = []
        for operation in action_to_operations['operations']:
            if operation not in policy_file['operations']:
                raise Exception('ERROR IN POLICY FILE: Operation is not present in the operations list')
            elif operation in operations:
                raise Exception('ERROR IN POLICY FILE: Duplicated operation in action_to_operations mapping')
            
            operations.append(operation)
    
    actions = []
    for action_policy in policy_file['action_policies']:
        if action_policy['action_name'] not in policy_file['actions']:
            raise Exception('ERROR IN POLICY FILE: Action is not present in the actions list')
        elif action_policy['action_name'] in actions:
            raise Exception('ERROR IN POLICY FILE: Duplicated policy for action')
        
        actions.append(action_policy['action_name'])

        if 'policies' not in action_policy.keys():
            raise Exception('ERROR IN POLICY FILE: No policy defined')
        
        policies = []
        for policy in action_policy['policies']:
            groups_present = 'groups' in policy.keys()
            rip_present = 'roles_in_projects' in policy.keys()

            if not groups_present and not rip_present:
                raise Exception('ERROR IN POLICY FILE: Missing groups or roles in projects in action policies')
            elif policy in policies:
                raise Exception('ERROR IN POLICY FILE: Duplicated policy definition')
            
            # TODO: Validate if rule is well specified

            policies.append(policy)
        
        if 'action_timeout' not in action_policy.keys():
            raise Exception('ERROR IN POLICY FILE: Missing action_timeout')
        elif not isinstance(action_policy['action_timeout'], int):
            raise Exception('ERROR IN POLICY FILE: Action timeout must be integer')
        elif action_policy['action_timeout'] < -1:
            raise Exception('ERROR IN POLICY FILE: Action timeout cannot be less than infinite (-1)')
        elif action_policy['action_timeout'] == 0:
            raise Exception('ERROR IN POLICY FILE: Action timeout cannot be 0 seconds')

    return policy_file


class PolicyValidator:
    POLICIES = validate_policy(json.load(open(Config.AUTHORIZATION_POLICY_FILE)))
    EXPIRATION_TIME = Config.REDIS_EXPIRATION_TIME
    USER_MARKER = Config.AUTHORIZATION_USER_MARKER
    ADMIN_MARKER = Config.AUTHORIZATION_ADMIN_MARKER
    SERVICE_MARKER = Config.AUTHORIZATION_SERVICE_MARKER    

    def __init__(self):
        if PolicyValidator.POLICIES is None:
            raise Exception('POLICY FILE NOT VALID')

        self.redis_db = redis.StrictRedis(host=Config.REDIS_URL, port=Config.REDIS_PORT)

    def generate_action_id(self, action):
        action_id = hashlib.sha512(str.encode(action + str(time.time())))

        while self.redis_db.exists(action_id):
            action_id = hashlib.sha512(str.encode(action + str(time.time())))

        return action_id

    def create_authorization(self, action, project, subject, service):
        try:
            if action not in PolicyValidator.POLICIES['actions']:
                return None

            # Check if service is service

            action_policy = filter(
                lambda x: x['action_name'] == action, 
                PolicyValidator.POLICIES['action_policies'])
            
            if len(action_policy) != 0:
                pass
                # Verify if subject/service match policy
            
            action_id = self.generate_action_id(action)

            action_grant = ActionGrant(action_id=action_id, action=action, project=project).to_public_dict()

            self.redis_db.hmset(action_id, action_grant)

            return action_grant
        except Exception as ex:
            print(ex)

            return None

    def verify_authorization(self, action_id, action, operation, project, client_service, server_service):
        try:
            if action not in PolicyValidator.POLICIES['actions']:
                return None
            
            if operation not in PolicyValidator.POLICIES['operations']:
                return None
            
            action_to_operations = filter(
                lambda x: x['action_name'] == action, 
                PolicyValidator.POLICIES['action_to_operations'])

            if operation not in action_to_operations:
                return None
            
            action_policy = filter(
                lambda x: x['action_name'] == action, 
                PolicyValidator.POLICIES['action_policies'])

            if len(action_policy) != 0:

                pass

            action_grant = ActionGrant(action_id=action_id, action=action, project=project).to_public_dict()

            return action_grant
        except Exception as ex:
            print(ex)

            return None