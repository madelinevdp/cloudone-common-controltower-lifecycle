import json
import logging
import time

import boto3

import c1wconnectorapi
import c1wresources
import cfnhelper
import ctlifecycleevent
import requests

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def get_org_id():
    client = boto3.client('organizations')
    return client.list_roots()["Roots"][0]['ARN'].rsplit(':')[4]


def create_oidc_provider(aws_account_id):
    sts_session = assume_role(aws_account_id, c1wresources.ControlTowerRoleName)
    client = sts_session.client('iam')
    logger.info(
        f'Creating role {c1wresources.IamRoleName}, policies {c1wresources.IamPolicyName1} & {c1wresources.IamPolicyName2}, and OIDC provider {c1wresources.OIDCProviderUrl} in account {aws_account_id}')
    path = "/"
    try:
        logger.info('Creating role...')
        client.create_role(Path=path, RoleName=c1wresources.IamRoleName,
                           AssumeRolePolicyDocument=c1wresources.get_assume_role_policy_document(aws_account_id, c1wresources.OIDCProviderUrl),
                           Description='CloudOne Integration Role created by Control Tower Master'
                           )
    except Exception as e:
        logger.info('Failed to create role')
        logger.info(e)
        raise e
    try:
        logger.info('Creating policy 1...')
        client.create_policy(PolicyName=c1wresources.IamPolicyName1,
                             PolicyDocument=json.dumps(c1wresources.policy_document_1)
                             )
    except Exception as e:
        logger.info('Failed to create policy 1')
        logger.info(e)
        raise e
    try:
        logger.info('Attaching policy 1...')
        client.attach_role_policy(PolicyArn=f'arn:aws:iam::{aws_account_id}:policy/{c1wresources.IamPolicyName1}',
                                  RoleName=c1wresources.IamRoleName
                                  )
    except Exception as e:
        logger.info('Failed to attach policy 1')
        logger.info(e)
        raise e
    try:
        logger.info('Creating policy 2...')
        client.create_policy(PolicyName=c1wresources.IamPolicyName2,
                             PolicyDocument=json.dumps(c1wresources.policy_document_2)
                             )
    except Exception as e:
        logger.info('Failed to create policy 2')
        logger.info(e)
        raise e
    try:
        logger.info('Attaching policy 2...')
        client.attach_role_policy(PolicyArn=f'arn:aws:iam::{aws_account_id}:policy/{c1wresources.IamPolicyName2}',
                                  RoleName=c1wresources.IamRoleName
                                  )
    except Exception as e:
        logger.info('Failed to attach policy 2')
        logger.info(e)
        raise e
    try:
        logger.info('Creating OIDC provider...')
        client.create_open_id_connect_provider(
            Url='https://74u3z7zmn1.execute-api.ca-central-1.amazonaws.com/dev-mvdpxx',
            ClientIDList=[f'arn:aws:iam::{aws_account_id}:root'],
            ThumbprintList=['9e99a48a9960b14926bb7f3b02e22da2b0ab7280'])
    except Exception as e:
        logger.info('Failed to create OIDC provider')
        logger.info(e)
        raise e
    else:
        return True


def delete_oidc_provider(aws_account_id):
    sts_session = assume_role(aws_account_id, c1wresources.ControlTowerRoleName)
    client = sts_session.client('iam')
    logger.info(f'Account is {boto3.client("sts").get_caller_identity()["Account"]}')
    try:
        logger.info(f'Detatching {c1wresources.IamPolicyName1}')
        client.detach_role_policy(
            PolicyArn=f'arn:aws:iam::{aws_account_id}:policy/{c1wresources.IamPolicyName1}',
            RoleName=c1wresources.IamRoleName
        )
        logger.info(f'Detached {c1wresources.IamPolicyName1}')
    except Exception as e:
        logger.info(
            f'Failed to detach policy {c1wresources.IamPolicyName1} from role {c1wresources.IamRoleName} \
                in account {aws_account_id}')
        logger.info(e)
    try:
        logger.info(f'Detatching {c1wresources.IamPolicyName2}')
        client.detach_role_policy(
            PolicyArn=f'arn:aws:iam::{aws_account_id}:policy/{c1wresources.IamPolicyName2}',
            RoleName=c1wresources.IamRoleName
        )
        logger.info(f'Detached {c1wresources.IamPolicyName2}')
    except Exception as e:
        logger.info(
            f'Failed to detach policy {c1wresources.IamPolicyName2} from role {c1wresources.IamRoleName} \
                in account {aws_account_id}')
        logger.info(e)
    try:
        logger.info(f'Deleting {c1wresources.IamRoleName}')
        client.delete_role(RoleName=c1wresources.IamRoleName)
        logger.info('Deleted role')
    except Exception as e:
        logger.info(f'Failed to delete role {c1wresources.IamRoleName} in account {aws_account_id}')
        logger.info(e)
    try:
        logger.info(f'Deleting {c1wresources.IamPolicyName1}')
        client.delete_policy(PolicyArn=f'arn:aws:iam::{aws_account_id}:policy/{c1wresources.IamPolicyName1}')
        logger.info('Deleted policy')
    except Exception as e:
        logger.info(
            "Failed to delete policy: {arn}".format(
                arn=f'arn:aws:iam::{aws_account_id}:policy/{c1wresources.IamPolicyName1}'))
        logger.info(e)
    try:
        logger.info(f'Deleting {c1wresources.IamPolicyName2}')
        client.delete_policy(PolicyArn=f'arn:aws:iam::{aws_account_id}:policy/{c1wresources.IamPolicyName2}')
        logger.info('Deleted policy')
    except Exception as e:
        logger.info(
            "Failed to delete policy: {arn}".format(
                arn=f'arn:aws:iam::{aws_account_id}:policy/{c1wresources.IamPolicyName2}'))
        logger.info(e)
    try:
        logger.info(f'Deleting OIDC provider {c1wresources.OIDCProviderUrl}')
        client.delete_open_id_connect_provider(OpenIDConnectProviderArn=f'arn:aws:iam::{aws_account_id}:oidc-provider/{c1wresources.OIDCProviderUrl}')
        logger.info('Deleted OIDC provider')
    except Exception as e:
        logger.info(f'Failed to delete OIDC provider {c1wresources.OIDCProviderUrl} in account {aws_account_id}')
    return


def assume_role(aws_account_number, role_name) -> boto3.Session:
    try:
        sts_client = boto3.client('sts')
        logger.info(f'Retrieving session for operation')
        logger.info(f'currently executing in '
                    f'{sts_client.get_caller_identity()["Account"]};'
                    f' called account is {aws_account_number}')
        if sts_client.get_caller_identity()["Account"] == aws_account_number:
            logger.info(f'Target account is Control Tower Master; returning local credentials session')
            return boto3.session.Session()
        partition = sts_client.get_caller_identity()['Arn'].split(":")[1]

        assume_role_response = sts_client.assume_role(
            RoleArn='arn:{}:iam::{}:role/{}'.format(
                partition, aws_account_number, role_name),
            RoleSessionName=str(aws_account_number + '-' + role_name)
        )
        sts_session = boto3.Session(
            aws_access_key_id=assume_role_response['Credentials']['AccessKeyId'],
            aws_secret_access_key=assume_role_response['Credentials']['SecretAccessKey'],
            aws_session_token=assume_role_response['Credentials']['SessionToken']
        )
        logger.info(f"Assumed session for {aws_account_number} - {role_name}.")
        return sts_session
    except Exception as e:
        logger.info(f"Could not assume role : {e}")
        raise e


def configure_account(aws_account_id):
    c1w_connector = c1wconnectorapi.CloudOneConnector(c1wresources.get_api_key())
    iam_client = boto3.client('iam')
    try:
        logger.info('Create Cloud One Integration')
        logger.info('Create OIDC resources in target account')
        create_oidc_provider(aws_account_id)
        time.sleep(20)
    except iam_client.exceptions.EntityAlreadyExistsException as e:
        logger.info("entity already exists")
        # update_policy(aws_account_id)
    except Exception as e:
        logger.info(f'Failed to configure account {aws_account_id} with exception: {e}')
    try:
        logger.info('Add integration to Cloud One')
        # return c1w_connector.add_connector(f'arn:aws:iam::{aws_account_id}:role/{c1wresources.IamRoleName}')
        #TODO get api key from secret
        c1_api_key = c1wresources.get_api_key()
        body = {'roleArn': f'arn:aws:iam::{aws_account_id}:role/{c1wresources.IamRoleName}'}
        bodyJson = json.dumps(body)
        response = requests.post(
            'https://74u3z7zmn1.execute-api.ca-central-1.amazonaws.com/dev-mvdpxx/api/cloudaccounts/aws', 
            data = bodyJson,
            headers = {'Api-Version': 'v1', 'Authorization': f'ApiKey {c1_api_key}'}
        )
        logger.info(response)
    except Exception as e:
        logger.info(f'Failed to add workload connector with exception {e}')


def remove_account_config(aws_account_id):
       
    try:
        logger.info(f'Removing Cloud One integration')
        # return c1w_connector.add_connector(f'arn:aws:iam::{aws_account_id}:role/{c1wresources.IamRoleName}')
        c1_api_key = c1wresources.get_api_key()
        response = requests.delete(
            f'https://74u3z7zmn1.execute-api.ca-central-1.amazonaws.com/dev-mvdpxx/api/cloudaccounts/aws/{aws_account_id}', 
            headers = {'Api-Version': 'v1', 'Authorization': f'ApiKey {c1_api_key}'}
        )
        logger.info(response)
    except Exception as e:
        logger.info(f'Failed to delete Cloud One integration with exception {e}')
    try:
        logger.info('Removing OIDC resources from target account')
        delete_oidc_provider(aws_account_id)
        logger.info(f'Removed OIDC resources from {aws_account_id}')
    except Exception as e:
        logger.info(f'Failed to remove OIDC resources from {aws_account_id} with exception: {e}')


def update_policy(aws_account_id, aws_account_name):
    logger.info(f'Updating account {aws_account_name} ({aws_account_id})')
    sts_session = assume_role(aws_account_id, c1wresources.ControlTowerRoleName)
    client = sts_session.client('iam')
    policy_resource = sts_session.resource('iam')
    logger.info(f'Updating policy in account {aws_account_id}')
    try:
        client.get_role(RoleName=c1wresources.IamRoleName)
    except client.exceptions.NoSuchEntityException:
        logger.info(f'Policy not found; configuring account')
        configure_account(aws_account_id)
        return
    logger.info(f'Updating AssumeRolePolicyDocument in account {aws_account_id}')
    try:
        update_assume_role_response = client.update_assume_role_policy(
            RoleName=c1wresources.IamRoleName,
            PolicyDocument=c1wresources.get_assume_role_policy_document(aws_account_id, c1wresources.OIDCProviderUrl)
        )
    except Exception as e:
        logger.info(f'Failed to update AssumeRolePolicyDocument: {e}')
        raise
    try:
        policy = policy_resource.Policy(f'arn:aws:iam::{aws_account_id}:policy/{c1wresources.IamPolicyName}')
        version = policy.default_version
        new_version_response = client.create_policy_version(
            PolicyArn=f'arn:aws:iam::{aws_account_id}:policy/{c1wresources.IamPolicyName}',
            PolicyDocument=json.dumps(c1wresources.policy_document),
            SetAsDefault=True
        )
        delete_old_version_response = client.delete_policy_version(
            PolicyArn=f'arn:aws:iam::{aws_account_id}:policy/{c1wresources.IamPolicyName}',
            VersionId=version.version_id
        )
    except Exception as e:
        logger.info(f'Failed to update policy {e}')
        raise


def get_accounts():
    account_infos = []
    client = boto3.client('organizations')
    paginator = client.get_paginator('list_accounts')
    page_iterator = paginator.paginate()
    for page in page_iterator:
        for account in page.get('Accounts'):
            acct_id = account["Id"]
            acct_name = account.get("Name", "")
            account_infos.append((acct_id, acct_name))
    return account_infos


def fresh_deploy(function_name):
    client = boto3.client('lambda')
    logger.info(f'Received function name {function_name} from context')
    count = 0
    for account_id, account_name in get_accounts():
        client.invoke(
            FunctionName=function_name,
            InvocationType='Event',
            Payload=json.dumps({'InvokeAction': 'configure_account', 'account_id': account_id})
        )
        count += 1
    print(f'Launched configure_account for {count} accounts')
    return None


def update_accounts(function_name):
    client = boto3.client('lambda')
    logger.info(f'Received function name {function_name} from context')
    count = 0
    for account_id, account_name in get_accounts():
        client.invoke(
            FunctionName=function_name,
            InvocationType='Event',
            Payload=json.dumps({'InvokeAction': 'update_account', 'account_id': account_id, 'account_name': account_name})
        )
        count += 1
    print(f'Launched update_accounts for {count} accounts')
    return None


def remove_all(function_name):
    client = boto3.client('lambda')
    logger.info(f'Received function name {function_name} from context')
    count = 0
    for account_id, account_name in get_accounts():
        client.invoke(
            FunctionName=function_name,
            InvocationType='Event',
            Payload=json.dumps({'InvokeAction': 'remove_account_config', 'account_id': account_id})
        )
        count += 1
    print(f'Launched remove_account_config for {count} accounts')
    return None


def lambda_handler(event, context):
    logger.info(f"Event received by handler: {event}")
    logger.info(f'function name: {context.function_name}\n'
                f'invoked arn: {context.invoked_function_arn}\n')
    if 'RequestType' in event:
        logger.info(f'Handling cloudformation Request')
        if event['RequestType'] == 'Create':
            logger.info(f"Received CFN create")
            response = cfnhelper.cfnResponse(event, context)
            try:
                fresh_deploy(context.function_name)
            except Exception as e:
                logger.info(f'Failed to handle create event with exception: {e}')
                response.send(cfnhelper.responseCode.FAILED)
            response.send(cfnhelper.responseCode.SUCCESS)
        # elif event['RequestType'] == 'Update':
        #     logger.info(f"Received CFN update")
        #     response = cfnhelper.cfnResponse(event, context)
        #     try:
        #         update_accounts(context.function_name)
        #     except Exception as e:
        #         logger.info(f'Failed to handle update event with exception: {e}')
        #         response.send(cfnhelper.responseCode.FAILED)
        #     response.send(cfnhelper.responseCode.SUCCESS)
        else:
            logger.info(f"Ignoring unhandled cfn request type: {event['RequestType']}")
            response = cfnhelper.cfnResponse(event, context)
            response.send(cfnhelper.responseCode.SUCCESS)
    elif 'InvokeAction' in event:
        if event['InvokeAction'] == 'configure_account':
            configure_account(event['account_id'])
        elif event['InvokeAction'] == 'configure_all':
            fresh_deploy(context.function_name)
        # elif event['InvokeAction'] == 'update_account':
        #     update_policy(event['account_id'], event['account_name'])
        elif event['InvokeAction'] == 'remove_account_config':
            remove_account_config(event['account_id'])
        elif event['InvokeAction'] == 'remove_all':
            remove_all(context.function_name)
    else:
        try:
            life_cycle_event = ctlifecycleevent.LifeCycleEvent(event)
        except Exception as e:
            logger.info(f'Did not find a supported event')
            return
        if life_cycle_event.create_account:
            configure_account(life_cycle_event.child_account_id)
        elif life_cycle_event.event_name == 'RemoveAccount':
            remove_account_config(life_cycle_event.child_account_id)
        else:
            logger.info(f'This is not an event handled by the integration. SKIPPING: {event}')
            response = cfnhelper.cfnResponse(event, context)
            response.send(cfnhelper.responseCode.FAILED)
        return False
