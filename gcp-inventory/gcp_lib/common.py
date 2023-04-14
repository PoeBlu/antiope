import json
import os
import time
import datetime
from dateutil import tz
import boto3
from botocore.exceptions import ClientError

from gcp_lib.project import *

import logging
logger = logging.getLogger()
logger.setLevel(logging.ERROR)
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)


def get_gcp_creds(secret_name):
    """
    Get the GCP service account key stored in AWS secrets manager.
    """

    client = boto3.client('secretsmanager')
    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        logger.critical(f"Unable to get secret value for {secret_name}: {e}")
        return(None)

    logger.debug(get_secret_value_response)
    if 'SecretString' in get_secret_value_response:
        secret_value = get_secret_value_response['SecretString']
    else:
        secret_value = get_secret_value_response['SecretBinary']

    try:
        return json.loads(secret_value)
    except Exception as e:
        logger.critical(f"Error during Credential and Service extraction: {e}")
        return(None)


def save_resource_to_s3(prefix, resource_id, resource):
    s3client = boto3.client('s3')
    try:
        object_key = f"GCP-Resources/{prefix}/{resource_id}.json"
        s3client.put_object(
            Body=json.dumps(resource, sort_keys=True, default=str, indent=2),
            Bucket=os.environ['INVENTORY_BUCKET'],
            ContentType='application/json',
            Key=object_key,
        )
    except ClientError as e:
        logger.error(f"Unable to save object {object_key}: {e}")


def get_active_projects():
    project_ids = get_all_project_ids(status="ACTIVE")
    return [GCPProject(project_id) for project_id in project_ids]


def get_all_project_ids(status=None):
    '''return an array of project_ids in the Projects table. Optionally, filter by status'''
    dynamodb = boto3.resource('dynamodb')
    project_table = dynamodb.Table(os.environ['PROJECT_TABLE'])

    project_list = []
    response = project_table.scan(
        AttributesToGet=['projectId', 'lifecycleState']
    )
    while 'LastEvaluatedKey' in response:
        # Means that dynamoDB didn't return the full set, so ask for more.
        project_list = project_list + response['Items']
        response = project_table.scan(
            AttributesToGet=['projectId', 'lifecycleState'],
            ExclusiveStartKey=response['LastEvaluatedKey']
        )
    project_list = project_list + response['Items']
    return [
        a['projectId']
        for a in project_list
        if status is None or a['lifecycleState'] == status
    ]
