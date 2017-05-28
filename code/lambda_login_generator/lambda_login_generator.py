from datetime import datetime
import json
import os
import uuid

import boto3
import requests
from retrying import retry

LAMBDA_EXECUTIONER_ROLE = os.getenv('EXECUTIONER_ROLE')
RETRY_PARAMS = {'wait_exponential_multiplier': 1000,
                'wait_exponential_max': 10000,
                'stop_max_attempt_number': 6
                }


class BaseGenerator(object):

    def __init__(self, context, **kwargs):
        self.context = context
        self.iam_client = boto3.client('iam')
        self.iam_resource = boto3.resource('iam')
        self.events_client = boto3.client('events')
        self.lambda_client = boto3.client('lambda')
        self.lambda_trust_statement = {'Action': 'sts:AssumeRole',
                                       'Effect': 'Allow',
                                       'Principal': {'AWS': LAMBDA_EXECUTIONER_ROLE}}
        self.lambda_trust_policy = {
            "Version": "2012-10-17",
            "Statement": [self.lambda_trust_statement]
        }

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

    @retry(**RETRY_PARAMS)
    def _assume_role(self, role_arn):
        sts_client = boto3.client('sts')
        session_name = str(uuid.uuid4())
        print 'Assuming session %s for role %s' % (session_name, role_arn)
        assumed_role = sts_client.assume_role(RoleArn=role_arn,
                                              RoleSessionName=session_name)
        print 'Successfully assumed session %s for role %s' % (session_name, role_arn)
        return assumed_role

    def schedule_delete(self):
        print 'Scheduling the removal of access in an hours time'
        rule_arn = self._create_cw_events_rule()
        self._permission_lambda(rule_arn)
        self._put_target(rule_arn)

    @retry(**RETRY_PARAMS)
    def _create_cw_events_rule(self):
        rule_name = 'temporary-login-cleanup-%s' % uuid.uuid4()
        now = datetime.now()
        # We're scheduling the removal for 1 hour in the future as that's how long the session can last at most
        scheduled_expression = 'cron(%s %s * * ? *)' % (now.minute, (now.hour + 1) % 24)
        print 'Creating CloudWatch Events Rule %s - %s' % (rule_name, scheduled_expression)
        response = self.events_client.put_rule(
            Name=rule_name,
            ScheduleExpression=scheduled_expression,
            State='ENABLED',
            Description='CloudWatch event to clean-up temporary login')
        print 'Successfully create CloudWatch Events Rule %s' % response['RuleArn']
        return response['RuleArn']

    @retry(**RETRY_PARAMS)
    def _permission_lambda(self, rule_arn):
        statement_id = rule_arn.split('/')[-1]
        print 'Adding invoke function statement: %s ' \
              'to lambda function: %s ' \
              'for rule: %s ' % (statement_id, self.context.function_name, rule_arn)
        self.lambda_client.add_permission(
            FunctionName=self.context.function_name,
            StatementId=statement_id,
            Action='lambda:InvokeFunction',
            Principal='events.amazonaws.com',
            SourceArn=rule_arn)
        print 'Successfully added invoke function statement: %s' % statement_id

    def cleanup(self, **kwargs):
        raise NotImplementedError

    def _put_target(self, rule_arn):
        # Override in child class
        raise NotImplementedError

    def clean_up_cw_event(self, rule_name):
        self._remove_permission(rule_name)  # We use the same name for statement_id as for rule_name
        self._remove_cw_events_rule(rule_name)

    @retry(**RETRY_PARAMS)
    def _remove_permission(self, statement_id):
        print 'Removing lambda invoke permission statement %s' % statement_id
        self.lambda_client.remove_permission(FunctionName=self.context.function_name,
                                             StatementId=statement_id)
        print 'Successfully removed lambda invoke permission statement %s' % statement_id

    @retry(**RETRY_PARAMS)
    def _remove_cw_events_rule(self, rule_name):
        print 'Removing CloudWatch Events rule targets %s' % rule_name
        self.events_client.remove_targets(Rule=rule_name, Ids=[rule_name])
        print 'Removing CloudWatch Events rule %s' % rule_name
        self.events_client.delete_rule(Name=rule_name)
        print 'Successfully removed CloudWatch Events rule %s' % rule_name


class RoleGenerator(BaseGenerator):

    def __init__(self, **kwargs):
        super(RoleGenerator, self).__init__(**kwargs)
        self.type = 'role'
        self.role_arn = kwargs.get('event_target')
        if self.role_arn:
            self.role_name = self.role_arn.split('/')[-1]

    def __call__(self):
        self._update_trust_policy()
        login_url = self.generate_login(self.role_arn)
        self.schedule_delete()
        return login_url

    @retry(**RETRY_PARAMS)
    def _update_trust_policy(self):
        assume_role_policy, existing_policy = self.get_assume_role_policy()
        existing_policy['Statement'].append(self.lambda_trust_statement)
        print 'Updating existing trust policy of %s' % self.role_name
        assume_role_policy.update(PolicyDocument=json.dumps(existing_policy))
        print 'Successfully updated trust policy of %s' % self.role_name

    def get_assume_role_policy(self):
        print 'Retrieving existing trust policy of %s' % self.role_name
        assume_role_policy = self.iam_resource.AssumeRolePolicy(self.role_name)
        existing_policy = assume_role_policy.Role().assume_role_policy_document
        return assume_role_policy, existing_policy

    @retry(**RETRY_PARAMS)
    def _put_target(self, rule_arn):
        rule_name = rule_arn.split('/')[-1]
        print 'Adding CloudWatch Events Rule target to rule: %s ' \
              'Target: %s ' \
              'Id: %s' % (rule_arn, self.context.invoked_function_arn, rule_name)
        custom_event_payload = {'rule_name': rule_name,
                                'type': self.type,
                                'role_arn': self.role_arn,
                                'action': 'cleanup'}
        self.events_client.put_targets(
            Rule=rule_name,
            Targets=[
                {
                    'Id': rule_name,
                    'Arn': self.context.invoked_function_arn,
                    'Input': json.dumps(custom_event_payload),
                }
            ]
        )
        print 'Successfully added CloudWatch Events Rule target to rule: %s ' \
              'Target: %s ' \
              'Id: %s' % (rule_arn, self.role_name, rule_name)

    @retry(**RETRY_PARAMS)
    def _restore_trust_policy(self):
        assume_role_policy, existing_policy = self.get_assume_role_policy()
        for statement in existing_policy['Statement']:
            if statement.get('Principal') and statement.get('Principal').get('AWS') == LAMBDA_EXECUTIONER_ROLE:
                print 'Removing statement %s from  Trust Policy on target role.' % statement
                existing_policy['Statement'].remove(statement)
        assume_role_policy.update(PolicyDocument=json.dumps(existing_policy))
        print 'Successfully removed temporary statement from Trust Policy on target role.'

    def cleanup(self, rule_name, role_arn, **kwargs):
        self.role_name = role_arn.split('/')[-1]
        self._restore_trust_policy()
        self.clean_up_cw_event(rule_name)


class PoliciesGenerator(BaseGenerator):
    def __init__(self, **kwargs):
        super(PoliciesGenerator, self).__init__(**kwargs)
        self.type = 'policies'
        self.managed_policies = kwargs.get('event_target')
        self.role_name = str(uuid.uuid4())

    def __call__(self):
        role = self._create_temp_role()
        self._attach_policies(role)
        login_url = self.generate_login(role.arn)
        self.schedule_delete()
        return login_url

    @retry(**RETRY_PARAMS)
    def _create_temp_role(self):
        print 'Creating temporary role %s' % self.role_name
        self.iam_client.create_role(RoleName=self.role_name,
                                    AssumeRolePolicyDocument=json.dumps(self.lambda_trust_policy))
        print 'Successfully create temporary role %s' % self.role_name
        return self.iam_resource.Role(self.role_name)

    @retry(**RETRY_PARAMS)
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

    def cleanup(self, rule_name, role_name, **kwargs):
        print 'Cleaning up config for %s' % rule_name
        self._delete_role(role_name)
        self.clean_up_cw_event(rule_name)
        print 'Cleanup finished'

    def _delete_role(self, role_name):
        print 'Deleting role %s' % role_name
        role = self.iam_resource.Role(role_name)
        for policy in role.attached_policies.all():
            print 'Removing attached policy %s' % policy.arn
            self._detach_policy(policy, role)
        self._delete_iam_role(role)
        print 'Successfully deleted role %s' % role_name

    @retry(**RETRY_PARAMS)
    def _detach_policy(self, policy, role):
        role.detach_policy(PolicyArn=policy.arn)

    @retry(**RETRY_PARAMS)
    def _delete_iam_role(self, role):
        role.delete()

    @retry(**RETRY_PARAMS)
    def _put_target(self, rule_arn):
        rule_name = rule_arn.split('/')[-1]
        print 'Adding CloudWatch Events Rule target to rule: %s ' \
              'Target: %s ' \
              'Id: %s' % (rule_arn, self.context.invoked_function_arn, rule_name)
        custom_event_payload = {'rule_name': rule_name,
                                'role_name': self.role_name,
                                'type': self.type,
                                'action': 'cleanup'}
        self.events_client.put_targets(
            Rule=rule_name,
            Targets=[
                {
                    'Id': rule_name,
                    'Arn': self.context.invoked_function_arn,
                    'Input': json.dumps(custom_event_payload),
                }
            ]
        )
        print 'Successfully added CloudWatch Events Rule target to rule: %s ' \
              'Target: %s ' \
              'Id: %s' % (rule_arn, self.role_name, rule_name)


GENERATOR_TYPES = {'role': RoleGenerator,
                   'policies': PoliciesGenerator}


def generate_login(event, context):
    event_type = event.get('type')
    event_target = event.get('target')
    return GENERATOR_TYPES.get(event_type)(context=context, event_target=event_target)()


def cleanup_login(event, context):
    event_type = event.get('type')
    GENERATOR_TYPES.get(event_type)(context=context).cleanup(**event)


action_types = {'generate': generate_login,
                'cleanup': cleanup_login}


def lambda_handler(event, context):
    action_type = event.get('action', 'generate')
    return action_types.get(action_type)(event, context)


if __name__ == '__main__':
    """ IGNORE THIS. Just for local testing."""
    client_event_body_1 = {
        "type": "role",
        "target": "arn:aws:iam::%s:role/test-tust-entity" % os.getenv('ACCOUNT_NUMBER')
    }
    client_event_body_1_cleanup = {'action': 'cleanup',
                                   'rule_name': 'temporary-login-cleanup-10c71aff-f736-497e-9ad4-844310a74bf7',
                                   'role_arn': 'arn:aws:iam::%s:role/test-tust-entity' % os.getenv('ACCOUNT_NUMBER'),
                                   'type': 'role'}
    client_event_body_2 = {
        "type": "policies",
        "target": ['ReadOnlyAccess', 'arn:aws:iam::%s:policy/test-user-managed-policy' % os.getenv('ACCOUNT_NUMBER')]
    }
    client_event_body_2_cleanup = {
        'rule_name': 'temporary-login-cleanup-5ea5950c-4903-47c1-8d98-eb9864b07c8e',
        'role_name': 'cfffaadf-eb10-4849-8568-6e4a1d184ae2',
        'type': 'policies',
        'action': 'cleanup'}

    context_obj = type('mock_context',
                       (object,),
                       {'function_name': 'test-event-body',
                        'invoked_function_arn': 'arn:aws:lambda:eu-west-1:%s:function:test-event-body'
                                                % os.getenv('ACCOUNT_NUMBER')}
                       )()
    lambda_handler(client_event_body_2_cleanup, context_obj)

