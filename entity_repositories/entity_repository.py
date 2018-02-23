from keystoneauth1 import session
from keystoneauth1.identity import v3
from keystoneauth1.exceptions.base import ClientException
from keystoneclient.v3 import client

import pprint
from settings import Config


class EntityInformation:
    def __init__(self, username, roles_in_projects, groups):
        self.username = username
        self.roles_in_projects = roles_in_projects
        self.groups = groups

    def to_dict(self):
        data = dict()

        data['username'] = self.username
        data['roles_in_projects'] = self.roles_in_projects
        data['groups'] = self.groups

        return data

class EntityRepository:
    def __init__(self):
        self.auth_url = Config.KEYSTONE_URL
        self.username = Config.KEYSTONE_USERNAME
        self.password = Config.KEYSTONE_PASSWORD
        self.project = Config.KEYSTONE_PROJECT
        self.admin_project = Config.KEYSTONE_ADMIN_PROJECT
        self.service_project = Config.KEYSTONE_SERVICE_PROJECT
        self.user_domain_name = Config.KEYSTONE_USER_DOMAIN_NAME
        self.project_domain_name = Config.KEYSTONE_PROJECT_DOMAIN_NAME
    
    def gather_information(self, username):
        def map_to_role_assignment_dict(role):
            role_assign = dict()

            role_assign['role'] = role.role.get('name')
            role_assign['project'] = role.scope.get('project').get('name')

            return role_assign
        
        def map_to_group_name(group):
            return group.name

        if username is None:
            return None
        
        try:
            auth = v3.Password(user_domain_name=self.user_domain_name,
                               username=self.username,
                               password=self.password,
                               project_domain_name=self.project_domain_name,
                               project_name=self.project,
                               auth_url=self.auth_url)
            sess = session.Session(auth=auth)
            keystone = client.Client(session=sess)

            user = list(filter(lambda x: x.name == username, keystone.users.list()))[0]

            role_assignments = list(map(
                map_to_role_assignment_dict, 
                keystone.role_assignments.list(user=user.id, include_names=True)))
            groups = list(map(map_to_group_name, keystone.groups.list(user=user.id)))

            return EntityInformation(
                username=user.name,
                roles_in_projects=role_assignments,
                groups=groups
            )
        except ClientException as ex:
            print(ex.message)

            return None
