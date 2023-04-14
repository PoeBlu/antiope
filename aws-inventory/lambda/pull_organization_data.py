import boto3
from botocore.exceptions import ClientError
import json
import os
import time

from lib.account import *
from lib.common import *

import logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)


# Lambda main routine
def handler(event, context):
    logger.info(f"Received event: {json.dumps(event, sort_keys=True)}")

    dynamodb = boto3.resource('dynamodb')
    account_table = dynamodb.Table(os.environ['ACCOUNT_TABLE'])

    account_list = []  # The list of accounts that will be processed by this StepFunction execution

    for payer_id in event['payer']:
        payer_creds = get_account_creds(payer_id)
        if payer_creds is False:
            logger.error(f"Unable to assume role in payer {payer_id}")
            continue

        logger.info(f"Processing payer {payer_id}")
        payer_account_list = get_consolidated_billing_subaccounts(payer_creds)
        for a in payer_account_list:
            a['Payer Id'] = payer_id

            # Update the stuff from AWS Organizations
            create_or_update_account(a, account_table)

            # Now test the cross-account role if the account is active
            if a[u'Status'] == "ACTIVE":
                my_account = AWSAccount(a['Id'])
                try:
                    creds = my_account.get_creds(session_name="test-audit-access")
                    # If an exception isn't thrown, this account is good.
                    # Add it to the list to process, and update the account's attribute
                    account_list.append(a['Id'])
                    my_account.update_attribute('cross_account_role', my_account.cross_account_role_arn)
                except AntiopeAssumeRoleError as e:
                    # Otherwise we log the error
                    logger.error(f"Unable to assume role into {a['Name']}({a['Id']})")
    event['account_list'] = account_list
    return(event)

# end handler()

##############################################


def get_account_creds(account_id):
    role_arn = f"arn:aws:iam::{account_id}:role/{os.environ['ROLE_NAME']}"
    client = boto3.client('sts')
    try:
        session = client.assume_role(RoleArn=role_arn, RoleSessionName=os.environ['ROLE_SESSION_NAME'])
        return(session['Credentials'])
    except Exception as e:
        logger.error(
            f"Failed to assume role {role_arn} in payer account {account_id}: {e}"
        )
        return(False)
# end get_account_creds()


def test_account_creds(account_id):
    role_arn = f"arn:aws:iam::{account_id}:role/{os.environ['ROLE_NAME']}"
    client = boto3.client('sts')
    try:
        session = client.assume_role(RoleArn=role_arn, RoleSessionName=os.environ['ROLE_SESSION_NAME'])
        return(role_arn)
    except Exception as e:
        logger.error(
            f"Failed to assume role {role_arn} in payer account {account_id}: {e}"
        )
        return(False)
# end test_account_creds()


def get_consolidated_billing_subaccounts(session_creds):
    # Returns: [
    #         {
    #             'Id': 'string',
    #             'Arn': 'string',
    #             'Email': 'string',
    #             'Name': 'string',
    #             'Status': 'ACTIVE'|'SUSPENDED',
    #             'JoinedMethod': 'INVITED'|'CREATED',
    #             'JoinedTimestamp': datetime(2015, 1, 1)
    #         },
    #     ],
    try:
        org_client = boto3.client('organizations',
            aws_access_key_id = session_creds['AccessKeyId'],
            aws_secret_access_key = session_creds['SecretAccessKey'],
            aws_session_token = session_creds['SessionToken']
        )
        output = []
        response = org_client.list_accounts(MaxResults=20)
        while 'NextToken' in response:
            output = output + response['Accounts']
            time.sleep(1)
            response = org_client.list_accounts(MaxResults=20, NextToken=response['NextToken'])

        return output + response['Accounts']
    except ClientError as e:
        if e.response['Error']['Code'] != 'AWSOrganizationsNotInUseException':
            raise ClientError(e)
        # This is a standalone account
        sts_client = boto3.client('sts',
            aws_access_key_id = session_creds['AccessKeyId'],
            aws_secret_access_key = session_creds['SecretAccessKey'],
            aws_session_token = session_creds['SessionToken']
        )
        response = sts_client.get_caller_identity()
        account = {
            'Id': response['Account'],
            'Name': response['Account'],
            'Status': "ACTIVE",  # Assume it is active since we could assumerole to it.
            'Email': "StandAloneAccount"
        }

        # If there is an IAM Alias, use that. There is no API to the account/billing portal we can
        # use to get an account name
        iam_client = boto3.client('iam',
            aws_access_key_id = session_creds['AccessKeyId'],
            aws_secret_access_key = session_creds['SecretAccessKey'],
            aws_session_token = session_creds['SessionToken']
        )
        response = iam_client.list_account_aliases()
        if 'AccountAliases' in response and len(response['AccountAliases']) > 0:
            account['Name'] = response['AccountAliases'][0]

        return([account])


# end get_consolidated_billing_subaccounts()


def create_or_update_account(a, account_table):
    logger.info(
        f"Adding account {a['Id']} with name {a['Name']} and email {a['Email']}"
    )
    if 'JoinedTimestamp' in a:
        a[u'JoinedTimestamp'] = a[u'JoinedTimestamp'].isoformat()  # Gotta convert to make the json save
    try:
        response = account_table.update_item(
            Key= {'account_id': a[u'Id']},
            UpdateExpression="set account_name=:name, account_status=:status, payer_id=:payer_id, root_email=:root_email, payer_record=:payer_record",
            ExpressionAttributeValues={
                ':name':        a[u'Name'],
                ':status':      a[u'Status'],
                ':payer_id':    a[u'Payer Id'],
                ':root_email':  a[u'Email'],
                ':payer_record': a
            }
        )

    except ClientError as e:
        raise AccountUpdateError(f"Unable to create {a['Name']}: {e}")
