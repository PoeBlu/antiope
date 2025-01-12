
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
    logger.debug("Received event: " + json.dumps(event, sort_keys=True))
    message = json.loads(event['Records'][0]['Sns']['Message'])
    logger.info("Received message: " + json.dumps(message, sort_keys=True))

    get_all = False
    if 'get-all-support-cases' in message:
        get_all = True

    try:
        target_account = AWSAccount(message['account_id'])
        support_client = target_account.get_client('support', region="us-east-1")  # Support API is in us-east-1 only
        cases = get_cases(target_account, support_client, get_all)
    except AntiopeAssumeRoleError as e:
        logger.error("Unable to assume role into account {}({})".format(target_account.account_name, target_account.account_id))
        return()
    except ClientError as e:
        if e.response['Error']['Code'] == "SubscriptionRequiredException":
            logger.error("Premium support is not enabled in {}({})".format(target_account.account_name, target_account.account_id))
            return()
        else:
            logger.critical("AWS Error getting info for {}: {}".format(target_account.account_name, e))
            raise
    except Exception as e:
        logger.critical("{}\nMessage: {}\nContext: {}".format(e, message, vars(context)))
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

    resource_item = {}
    resource_item['awsAccountId']                   = target_account.account_id
    resource_item['awsAccountName']                 = target_account.account_name
    resource_item['resourceType']                   = "AWS::Support::Case"
    resource_item['source']                         = "Antiope"

    resource_item['configurationItemCaptureTime']   = str(datetime.datetime.now())
    resource_item['configuration']                  = c
    resource_item['supplementaryConfiguration']     = {}
    resource_item['resourceId']                     = c['caseId']
    resource_item['resourceName']                   = c['displayId']
    resource_item['errors']                         = {}

    save_resource_to_s3(RESOURCE_PATH, f"{target_account.account_id}-{c['caseId']}", resource_item)
