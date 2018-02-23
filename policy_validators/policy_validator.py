import re, json, redis, hashlib, time
from settings import Config

class ActionGrant:
    def __init__(self, action_id, action, project, ns_id, subject, service, operations=[]):
        self.action_id = action_id
        self.action = action
        self.project = project
        self.ns_id = ns_id
        self.subject = subject
        self.service = service
        self.operations = operations
    
    def to_public_dict(self):
        data = dict()

        data['action_id'] = self.action_id
        data['action'] = self.action
        data['project'] = self.project
        data['ns_id'] = self.ns_id

        return data

    def to_redis_dict(self):
        data = dict()

        data['action_id'] = self.action_id
        data['action'] = self.action
        data['project'] = self.project
        data['ns_id'] = self.ns_id
        data['subject'] = self.subject.to_dict()
        data['service'] = self.service.to_dict()
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
            groups_present = 'group' in policy.keys()
            rip_present = 'role_in_project' in policy.keys()

            if not groups_present and not rip_present:
                raise Exception('ERROR IN POLICY FILE: Missing groups or roles in projects in action policies')
            elif policy in policies:
                raise Exception('ERROR IN POLICY FILE: Duplicated policy definition')
            
            if rip_present is True:
                if 'role' not in policy['role_in_project'].keys():
                    raise Exception('ERROR IN POLICY FILE: Mising role in role in project policy')
                elif 'project' not in policy['role_in_project'].keys():
                    raise Exception('ERROR IN POLICY FILE: Missing project in role in project policy')

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
    SERVICE_RP = dict(role=Config.SERVICE_ROLE, project=Config.SERVICE_PROJECT)

    def __init__(self):
        if PolicyValidator.POLICIES is None:
            raise Exception('POLICY FILE NOT VALID')

        self.redis_db = redis.StrictRedis(host=Config.REDIS_URL, port=Config.REDIS_PORT)

    def generate_action_id(self, action):
        action_id = hashlib.sha512(str.encode(action + str(time.time()))).hexdigest()

        while self.redis_db.exists(action_id):
            action_id = hashlib.sha512(str.encode(action + str(time.time()))).hexdigest()

        return action_id

    def create_authorization(self, action, project, ns_id, subject, service):
        if PolicyValidator.POLICIES is None:
            raise Exception('POLICY FILE NOT VALID')

        try:
            # Checking if action in action list
            if action not in PolicyValidator.POLICIES['actions']:
                print('action not present in action list')
                return None

            # Checking if service is a service
            if PolicyValidator.SERVICE_RP not in service.roles_in_projects:
                print('service is not a service')
                return None

            # Getting action policy
            action_policy = list(filter(
                lambda x: x['action_name'] == action, 
                PolicyValidator.POLICIES['action_policies']))
            
            # If there is an action, there is a need to authorize the subject making the request
            found_policy = False
            if len(action_policy) != 0:
                for policy in action_policy[0]['policies']:
                    has_group = policy.get('group') is not None
                    valid_group = policy.get('group') in subject.groups
                    has_rip = policy.get('role_in_project') is not None
                    valid_rip = policy.get('role_in_project') in subject.roles_in_projects

                    if has_group is True and has_rip is True:
                        found_policy = valid_group and valid_rip
                    elif has_group is True:
                        found_policy = valid_group
                    elif has_rip:
                        found_policy = valid_rip
            
                    if found_policy is True:
                        break
            # If no policy was defined, all the users are allowed
            else:
                found_policy = True
            
            # Only false if the user doesn't have the required permissions
            if found_policy is False:
                print('user does not have the right permissions')
                return None
           
            # Generating an action id (also needed for auditing purposes)
            action_id = self.generate_action_id(action)

            # Creating action to be stored in Redis
            action_grant = ActionGrant(action_id=action_id, action=action, project=project, ns_id=ns_id, subject=subject, service=service)
            self.redis_db.set(action_id, json.dumps(action_grant.to_redis_dict()))

            # Checking for action timeout values and setting if necessary
            if len(action_policy) != 0:
                timeout = action_policy[0].get('action_timeout')

                if timeout > 0:
                    self.redis_db.expire(action_id, timeout)

            return action_grant.to_public_dict()
        except Exception as ex:
            print(ex)

            return None

    def verify_authorization(self, action_id, action, operation, project, ns_id, client_service, server_service):
        if PolicyValidator.POLICIES is None:
            raise Exception('POLICY FILE NOT VALID')

        try:
            # Verify if action is in actions list
            if action not in PolicyValidator.POLICIES['actions']:
                print('action is not in action list')
                return None
            
            # Verify if operation is in operations list
            if operation not in PolicyValidator.POLICIES['operations']:
                print('operation is not in operation list')
                return None
            
            # Verify if operation is in action to operations mapping
            action_to_operations = list(filter(
                lambda x: x['action_name'] == action, 
                PolicyValidator.POLICIES['action_to_operations']))[0]

            if operation not in action_to_operations['operations']:
                print('operation is not action to operations mapping')
                return None

            # Verify if action was approved
            if self.redis_db.exists(action_id) is False:
                print('action_id is not valid')
                return None

            # Getting information about the action grant
            action_grant = json.loads(self.redis_db.get(action_id).decode('utf-8'))

            # Checking if information is accurate
            if action_grant.get('action') != action:
                print('action does not match stored action')
                return None
            elif action_grant.get('action_id') != action_id:
                print('action_id does not match stored action id')
                return None
            elif action_grant.get('ns_id') != ns_id:
                print('ns id does not match stored ns id')
                return None

            # Appending the requested operation to the action grant
            operations = action_grant.get('operations').append(operation)
            action_grant['operations'] = operations

            # Checking for expiration time on the action
            ttl = self.redis_db.ttl(action_id)

            self.redis_db.set(action_id, action_grant)

            # If the action has a timeout associated with it, putting the remaining time back in redis
            if ttl > 0:
                self.redis_db.expire(action_id, ttl)

            action_grant.pop('subject', None)
            action_grant.pop('service', None)
            action_grant.pop('operations', None)

            return action_grant
        except Exception as ex:
            print(ex)

            return None
