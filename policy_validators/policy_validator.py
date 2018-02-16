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
    def __init__(self):
        pass
    
    def create_authorization(self, action, project, subject, service):
        return ActionGrant(action_id=0, audit_id=0, action=action, project=project)

    def verify_authorization(self, action, project, client_service, server_service):
        return ActionGrant(action_id=0, audit_id=0, action=action, project=project)
