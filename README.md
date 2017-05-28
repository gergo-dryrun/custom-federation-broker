# Custom Federation Broker for Console Access

If you ever came across the need to grant somebody console access to your AWS account, you are familiar with the tedious process of creating an user, configuring permissions and keeping track of the user.

A common alternative is to use `SAML 2.0 Federated Access`, either by configuring an on-premise IdentityProvider, such as `Microsoft Active Directory Federation Service` or, the open-source alternative, `Shibboleth`. If you want to know more about getting started on that I highly recommend [Single Sign-On: Integrating AWS, OpenLDAP, and Shibboleth whitepaper.](http://d0.awsstatic.com/whitepapers/aws-whitepaper-single-sign-on-integrating-aws-open-ldap-and-shibboleth.pdf) <sup>[1](#myfootnote1)</sup>

However, if don't want to go as far as setting up ADFS or Shibboleth, there's another option: creating your own `Custom Federation Broker`, and that's what the lambda within this repository is.

Because we are dealing with IAM, which is in its nature highly sensitive, I **strongly** recommend you check out the repository and give the `code/lambda_login_generator/lambda_login_generator.py` a read-through.
Not that you shouldn't trust me, but it's best to be aware of the things that you decide to deploy in your AWS account.

Once you forked the repo, you deploy your own stack using the attached Makefile:

```bash
make BUCKET_NAME=existing_bucket_of_choice STACK_NAME=login-generator deploy
```

The `BUCKET_NAME` specifies where the lambda function artifacts will be uploaded, so make sure that the bucket exists and you have access to it.

This will provision the necessary lambda function and the executioner role.

Once you have the lambda running, you can use the CLI script from `code/cli_login_generator/` to generate temporary console login URLs.

You can specify a comma separated list of managed policies, both AWS managed policies and customer managed policies are supported.

```bash
./login_generator_client.py --policies ReadOnlyAccess,arn:aws:iam::<YOUR_ACCOUNT_NUMBER>:policy/your-customer-managed-policy
```

Or you can specify the name of an existing IAM role.

```bash
./login_generator_client.py --role arn:aws:iam::<YOUR_ACCOUNT_NUMBER>:role/custom-role
```

If in doubt, use `--help`

```
$./login_generator_client.py --help
Usage: login_generator_client.py [OPTIONS]

Options:
  --role TEXT                  ARN of the role that you want to assume.
                               Example: arn:aws:iam::<YOUR_ACC_NUMBER>:role
                               /demo-role
  --policies TEXT              Comma separated list of managed policies.
                               Example: ReadOnlyAccess,arn:aws:iam::<YOUR_ACC_
                               NUMBER>:policy/my-managed-policy
  --lambda_function_name TEXT  Name of login URL generator lambda function.
  --help                       Show this message and exit.

```

### Implementation details

#### Managed policies

If you decide to use the `--policies` option then a temporary role will be created which contains all the managed policies you passed in.

Once the role exists, we invoke `AWS STS AssumeRole` on it. With the set of temporary credentials from AssumeRole, we will call the `AWS federation endpoint`.

The federation endpoint will return a short-lived login URL.

#### Existing Role

If you want to create the session based of an existing role then you use the `--role` argument and specify the role ARN.

The lambda will add a `Statement` to the `Trust Policy` of the role which will allow the lambda to assume it. Then we assume the role, pass the obtained temporary credentials to `AWS Federation endpoint` and get back the short-lived login URL.

For both scenarios, at the end of generating the login URL, we create a `CloudWatch Events` rule to invoke the same lambda after an hour to do a clean-up of anything that was modified during the login URL generation, including the event rule that invoked the clean-up process.

For `managed policies` option this means detaching the managed policies and deleting the temporary role. For `existing role` option, this means removing the statement allowing AssumeRole from the Trust Policy of the target role, thus restoring it to its original state.


And there you go, now you have a simple and reliable way to grant others console access to your AWS account.

#### Tips and gotchas
 * Keep in mind that the URL grants access to your AWS resources through the AWS Management Console to the extent that you have enabled permissions in the associated temporary security credentials. For this reason, you should treat the URL as a secret.
 * Even though the federated login session lasts an hour, the login link is only valid for 15 minutes after generation.

#### Requirements

* [awscli](http://docs.aws.amazon.com/cli/latest/userguide/installing.html) version >=1.11.36
* [click](http://click.pocoo.org/5/) version >=6.7
* [boto3](http://boto3.readthedocs.io/en/latest/) version >=1.4.4

***

<a name="myfootnote1">1</a>: I do plan on having an entry/project dedicated to that in the near-future.