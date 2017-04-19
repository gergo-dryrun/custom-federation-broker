import json
import uuid

import boto3
import requests


def lambda_handler(event, context):

    client = boto3.client('sts')
    session_name = str(uuid.uuid4())
    assumed_role = client.assume_role(RoleArn='TARGET_ROLE_ARN',
                                      RoleSessionName=session_name)

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

if __name__ == '__main__':
    lambda_handler(None, None)

