import boto3
from botocore.exceptions import ClientError

import json
import os
import time
import datetime

from mako.template import Template

from lib.account import *
from lib.common import *

import logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)

assume_role_link = "<a href=\"https://signin.aws.amazon.com/switchrole?account={}&roleName={}&displayName={}\">{}</a>"


# Lambda main routine
def handler(event, context):
    logger.info(f"Received event: {json.dumps(event, sort_keys=True)}")

    # We will make a HTML Table and a Json file with this data

    json_data = []

    # Cache account_name for all the parent accounts
    payers = {}

    # Data to be saved to S3 and used to generate the template report
    json_data = {"accounts": []}

    # Get and then sort the list of accounts by name, case insensitive.
    active_accounts = get_active_accounts()
    active_accounts.sort(key=lambda x: x.account_name.lower())

    for a in active_accounts:
        logger.info(a.account_name)

        # We don't want to save the entire object's attributes.
        j = a.db_record.copy()

        try:
            if str(a.payer_id) in payers:
                j['payer_name'] = payers[str(a.payer_id)]
            else:
                payer = AWSAccount(str(a.payer_id))
                j['payer_name'] = payer.account_name
                payers[payer.account_id] = payer.account_name
        except AccountLookupError:
            j['payer_name'] = "Not Found"

        # Build the cross account role link
        if hasattr(a, 'cross_account_role') and a.cross_account_role is not None:
            j['assume_role_link'] = assume_role_link.format(a.account_id, os.environ['ROLE_NAME'], a.account_name, os.environ['ROLE_NAME'])
        else:
            j['assume_role_link'] = "No Cross Account Role"
        json_data['accounts'].append(j)

    json_data['timestamp'] = datetime.datetime.now()
    json_data['account_count'] = len(active_accounts)
    json_data['bucket'] = os.environ['INVENTORY_BUCKET']

    s3_client = boto3.client('s3')

    try:
        response = s3_client.get_object(
            Bucket=os.environ['INVENTORY_BUCKET'],
            Key='Templates/account_inventory.html'
        )
        mako_body = str(response['Body'].read().decode("utf-8"))
    except ClientError as e:
        logger.error(f"ClientError getting HTML Template: {e}")
        raise

    result = Template(mako_body).render(**json_data)

    try:
        response = s3_client.put_object(
            # ACL='public-read',
            Body=result,
            Bucket=os.environ['INVENTORY_BUCKET'],
            ContentType='text/html',
            Key='Reports/account_inventory.html',
        )

        # Save the JSON to S3
        response = s3_client.put_object(
            # ACL='public-read',
            Body=json.dumps(json_data, sort_keys=True, indent=2, default=str),
            Bucket=os.environ['INVENTORY_BUCKET'],
            ContentType='application/json',
            Key='Reports/account_inventory.json',
        )
    except ClientError as e:
        logger.error(f"ClientError saving report: {e}")
        raise

    return(event)
