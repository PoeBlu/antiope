
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

RESOURCE_PATH = "support/trustedadvisorcheckresult"

# TA Checks by category (as of 3/6/19)
#  9             "category": "cost_optimizing",
# 24             "category": "fault_tolerance",
# 11             "category": "performance",
# 17             "category": "security",
# 48             "category": "service_limits",

# This is what I think we should care about
CATEGORIES = ['security', 'fault_tolerance', 'service_limits']


def lambda_handler(event, context):
    logger.debug(f"Received event: {json.dumps(event, sort_keys=True)}")
    message = json.loads(event['Records'][0]['Sns']['Message'])
    logger.info(f"Received message: {json.dumps(message, sort_keys=True)}")

    try:
        target_account = AWSAccount(message['account_id'])
        support_client = target_account.get_client('support', region="us-east-1")  # Support API is in us-east-1 only
        checks = get_checks(target_account, support_client)
        for c in checks:
            process_ta_check(target_account, support_client, c)

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


def get_checks(target_account, client):
    '''Get a List of all the trusted advisor checks, return those that match CATEGORIES'''

    response = client.describe_trusted_advisor_checks(language='en')
    return [c for c in response['checks'] if c['category'] in CATEGORIES]


def process_ta_check(target_account, client, c):
    '''Get the check results for each check'''

    response = client.describe_trusted_advisor_check_result(checkId=c['id'])
    if 'result' not in response:
        logger.error(f"Unable to get TA Check Results for checkId {c['id']} / {c['name']}")
        return()

    check = response['result']
    logger.debug(check)

    # There are a lot of TA checks. We don't need to capture the ones where it's all Ok.
    if check['status'] == "ok":
        return()

    resource_item = {
        'awsAccountId': target_account.account_id,
        'awsAccountName': target_account.account_name,
        'resourceType': "AWS::TrustedAdvisor::CheckResult",
        'source': "Antiope",
        'configurationItemCaptureTime': str(datetime.datetime.now()),
        'configuration': check,
        'supplementaryConfiguration': {},
    }
    resource_item['supplementaryConfiguration']['CheckData'] = c
    resource_item['resourceId']                     = check['checkId']
    resource_item['resourceName']                   = c['name']
    resource_item['errors']                         = {}

    save_resource_to_s3(RESOURCE_PATH, f"{target_account.account_id}-{check['checkId']}", resource_item)
