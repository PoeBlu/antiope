
import boto3
from botocore.exceptions import ClientError

import json
import os
import time
import datetime
from dateutil import tz

from lib.account import *
from lib.common import *

import logging
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)

RESOURCE_PATH = "support/case"


def lambda_handler(event, context):
    logger.debug(f"Received event: {json.dumps(event, sort_keys=True)}")
    message = json.loads(event['Records'][0]['Sns']['Message'])
    logger.info(f"Received message: {json.dumps(message, sort_keys=True)}")

    get_all = 'get-all-support-cases' in message
    try:
        target_account = AWSAccount(message['account_id'])
        support_client = target_account.get_client('support', region="us-east-1")  # Support API is in us-east-1 only
        cases = get_cases(target_account, support_client, get_all)
    except AntiopeAssumeRoleError as e:
        logger.error(
            f"Unable to assume role into account {target_account.account_name}({target_account.account_id})"
        )
        return()
    except ClientError as e:
        if e.response['Error']['Code'] == "SubscriptionRequiredException":
            logger.error(
                f"Premium support is not enabled in {target_account.account_name}({target_account.account_id})"
            )
            return()
        else:
            logger.critical(
                f"AWS Error getting info for {target_account.account_name}: {e}"
            )
            raise
    except Exception as e:
        logger.critical(f"{e}\nMessage: {message}\nContext: {vars(context)}")
        raise


def get_cases(target_account, client, get_all):
    '''Get a List of all the trusted advisor cases, return those that match CATEGORIES'''
    cases = []
    response = client.describe_cases(includeResolvedCases=get_all)
    while 'NextToken' in response:
        for c in response['cases']:
            process_case(target_account, client, c)
        response = client.describe_cases(includeResolvedCases=get_all, NextToken=response['NextToken'])
    for c in response['cases']:
        process_case(target_account, client, c)


def process_case(target_account, client, c):
    '''Get the check results for each check'''

    resource_item = {
        'awsAccountId': target_account.account_id,
        'awsAccountName': target_account.account_name,
        'resourceType': "AWS::Support::Case",
        'source': "Antiope",
        'configurationItemCaptureTime': str(datetime.datetime.now()),
    }
    resource_item['configuration']                  = c
    resource_item['supplementaryConfiguration']     = {}
    resource_item['resourceId']                     = c['caseId']
    resource_item['resourceName']                   = c['displayId']
    resource_item['errors']                         = {}

    save_resource_to_s3(RESOURCE_PATH, f"{target_account.account_id}-{c['caseId']}", resource_item)
