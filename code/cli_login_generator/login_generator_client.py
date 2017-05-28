#!/usr/bin/env python
"""
A sample client to invoke the Login URL Generator Lambda function and return a short lived login URL.
"""

import json

import boto3
import click


@click.command()
@click.option('--role',
              help='ARN of the role that you want to assume.\n'
                   'Example: arn:aws:iam::<YOUR_ACC_NUMBER>:role/demo-role',
              required=False)
@click.option('--policies',
              help='Comma separated list of managed policies.\n'
                   'Example: ReadOnlyAccess,arn:aws:iam::<YOUR_ACC_NUMBER>:policy/my-managed-policy',
              required=False)
@click.option('--lambda_function_name',
              help='Name of login URL generator lambda function.',
              required=False,
              default='lambda_login_generator')
def main(role, policies, lambda_function_name):
    if not any([role, policies]) or all([role, policies]):
        print 'You must specify either a role or a list of policies. \n' \
              'Please see ./login_generator_client.py --help.'
        return -1

    lambda_client = boto3.client('lambda')
    if policies:
        payload = {
            'type': 'policies',
            'target': policies.split(',')
        }
    else:
        payload = {
            'type': 'role',
            'target': role
        }

    response = lambda_client.invoke(FunctionName=lambda_function_name,
                                    InvocationType='RequestResponse',
                                    LogType='None',
                                    Payload=json.dumps(payload))
    print response['Payload'].read()


if __name__ == '__main__':
    main()
