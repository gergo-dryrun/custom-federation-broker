import json
import os
import uuid

import boto3
import requests
from retrying import retry

LAMBDA_EXECUTIONER_ROLE = os.getenv('EXECUTIONER_ROLE')


class BaseGenerator(object):
    def __init__(self):
        self.iam_client = boto3.client('iam')
        self.iam_resource = boto3.resource('iam')
        self.lambda_trust_statement = {'Action': 'sts:AssumeRole',
                                       'Effect': 'Allow',
                                       'Principal': {'AWS': LAMBDA_EXECUTIONER_ROLE}}
        self.lambda_trust_policy = {
            "Version": "2012-10-17",
            "Statement": [self.lambda_trust_statement]
        }

    @retry(wait_exponential_multiplier=1000,
           wait_exponential_max=10000,
           stop_max_attempt_number=10)
    def _assume_role(self, role_arn):
        sts_client = boto3.client('sts')
        session_name = str(uuid.uuid4())
        print 'Assuming session %s for role %s' % (session_name, role_arn)
        assumed_role = sts_client.assume_role(RoleArn=role_arn,
                                              RoleSessionName=session_name)
        print 'Successfully assumed session %s for role %s' % (session_name, role_arn)
        return assumed_role

    def generate_login(self, role_arn):
        assumed_role = self._assume_role(role_arn)
        temp_credentials = {'sessionId': assumed_role['Credentials']['AccessKeyId'],
                            'sessionKey': assumed_role['Credentials']['SecretAccessKey'],
                            'sessionToken': assumed_role['Credentials']['SessionToken']
                            }
        request_parameters = {'Action': 'getSigninToken',
                              'Session': json.dumps(temp_credentials)
                              }
        resp = requests.get("https://signin.aws.amazon.com/federation",
                            params=request_parameters)
        signin_token = resp.json()
        request_parameters = {'Action': 'login',
                              'Issuer': 'demo-issuer',
                              'Destination': 'https://console.aws.amazon.com/',
                              'SigninToken': signin_token['SigninToken']
                              }
        req = requests.Request('GET',
                               'https://signin.aws.amazon.com/federation',
                               params=request_parameters)
        request = req.prepare()

        return request.url


class RoleGenerator(BaseGenerator):
    def __init__(self, role_arn):
        super(RoleGenerator, self).__init__()
        self.role_arn = role_arn
        self.role_name = role_arn.split('/')[-1]

    def __call__(self):
        self._update_trust_policy()
        return self.generate_login(self.role_arn)

    @retry(wait_exponential_multiplier=1000,
           wait_exponential_max=10000,
           stop_max_attempt_number=10)
    def _update_trust_policy(self):
        print 'Retrieving existing trust policy of %s' % self.role_name
        assume_role_policy = self.iam_resource.AssumeRolePolicy(self.role_name)
        existing_policy = assume_role_policy.Role().assume_role_policy_document
        existing_policy['Statement'].append(self.lambda_trust_statement)
        print 'Updating existing trust policy of %s' % self.role_name
        assume_role_policy.update(PolicyDocument=json.dumps(existing_policy))
        print 'Successfully updated trust policy of %s' % self.role_name


class PoliciesGenerator(BaseGenerator):
    def __init__(self, policies):
        super(PoliciesGenerator, self).__init__()
        self.managed_policies = policies
        self.role_name = str(uuid.uuid4())

    def __call__(self):
        role = self._create_temp_role()
        self._attach_policies(role)
        return self.generate_login(role.arn)

    @retry(wait_exponential_multiplier=1000,
           wait_exponential_max=10000,
           stop_max_attempt_number=10)
    def _attach_policies(self, role):
        for policy in self.managed_policies:
            if 'arn:aws:iam' not in policy:
                managed_policy_arn = 'arn:aws:iam::aws:policy/%s' % policy
            else:
                # This way we handle user managed policies as well
                managed_policy_arn = policy
            print 'Attaching managed policy %s' % managed_policy_arn
            role.attach_policy(PolicyArn=managed_policy_arn)
            print 'Successfully attached policy %s' % managed_policy_arn

    @retry(wait_exponential_multiplier=1000,
           wait_exponential_max=10000,
           stop_max_attempt_number=1)
    def _create_temp_role(self):
        print 'Creating temporary role %s' % self.role_name
        self.iam_client.create_role(RoleName=self.role_name,
                                    AssumeRolePolicyDocument=json.dumps(self.lambda_trust_policy))
        print 'Successfully create temporary role %s' % self.role_name
        return self.iam_resource.Role(self.role_name)


generator_types = {'role': RoleGenerator,
                   'policies': PoliciesGenerator}


def lambda_handler(event, context):
    event_type = event['type']
    event_target = event['target']
    print generator_types.get(event_type)(event_target)()


if __name__ == '__main__':
    client_event_body_1 = {
        "type": "role",
        "target": "arn:aws:iam::%s:role/test-tust-entity" % os.getenv('ACCOUNT_NUMBER')
    }
    client_event_body_2 = {
        "type": "policies",
        "target": ['ReadOnlyAccess', 'arn:aws:iam::%s:policy/test-user-managed-policy' % os.getenv('ACCOUNT_NUMBER')]
    }
    lambda_handler(client_event_body_2, None)

scheduled_event_body = {
    "account": "123456789012",
    "region": "us-east-1",
    "detail": {},
    "detail-type": "Scheduled Event",
    "source": "aws.events",
    "time": "1970-01-01T00:00:00Z",
    "id": "cdc73f9d-aea9-11e3-9d5a-835b769c0d9c",
    "resources": [
        "arn:aws:events:us-east-1:123456789012:rule/my-schedule"
    ]
}
