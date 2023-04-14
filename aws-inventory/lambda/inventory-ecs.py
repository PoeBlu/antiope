import boto3
from botocore.exceptions import ClientError, ParamValidationError

import json
import os
import time
import datetime
from dateutil import tz

from lib.account import *
from lib.common import *

import logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)

CLUSTER_RESOURCE_PATH = "ecs/cluster"
TASK_RESOURCE_PATH = "ecs/task"


def lambda_handler(event, context):
    logger.debug(f"Received event: {json.dumps(event, sort_keys=True)}")
    message = json.loads(event['Records'][0]['Sns']['Message'])
    logger.info(f"Received message: {json.dumps(message, sort_keys=True)}")

    try:

        target_account = AWSAccount(message['account_id'])

        regions = target_account.get_regions()
        if 'region' in message:
            regions = [message['region']]

        # describe ec2 instances
        for r in regions:
            ecs_client = target_account.get_client('ecs', region=r)

            for cluster_arn in list_clusters(ecs_client):
                cluster = ecs_client.describe_clusters(clusters=[cluster_arn], include=['STATISTICS', 'TAGS'])['clusters'][0]

                cluster_item = {
                    'awsAccountId': target_account.account_id,
                    'awsAccountName': target_account.account_name,
                    'resourceType': "AWS::ECS::Cluster",
                    'source': "Antiope",
                    'configurationItemCaptureTime': str(
                        datetime.datetime.now()
                    ),
                }
                cluster_item['awsRegion']                      = r
                cluster_item['configuration']                  = cluster
                if 'tags' in cluster:
                    cluster_item['tags']                       = parse_ecs_tags(cluster['tags'])
                cluster_item['supplementaryConfiguration']     = {}
                cluster_item[
                    'resourceId'
                ] = f"{cluster['clusterName']}-{target_account.account_id}"
                cluster_item['resourceName']                   = cluster['clusterName']
                cluster_item['ARN']                            = cluster['clusterArn']
                cluster_item['errors']                         = {}
                save_resource_to_s3(CLUSTER_RESOURCE_PATH, cluster_item['resourceId'], cluster_item)

                for task_arn in list_tasks(ecs_client, cluster_arn):

                    # Lambda's boto doesn't yet support this API Feature
                    try:
                        task = ecs_client.describe_tasks(cluster=cluster_arn, tasks=[task_arn], include=['TAGS'])['tasks'][0]
                    except ParamValidationError as e:
                        import botocore
                        logger.error(f"Unable to fetch Task Tags - Lambda Boto3 doesn't support yet. Boto3: {boto3.__version__} botocore: {botocore.__version__}")
                        task = ecs_client.describe_tasks(cluster=cluster_arn, tasks=[task_arn])['tasks'][0]

                    task_item = {
                        'awsAccountId': target_account.account_id,
                        'awsAccountName': target_account.account_name,
                        'resourceType': "AWS::ECS::Task",
                        'source': "Antiope",
                        'configurationItemCaptureTime': str(
                            datetime.datetime.now()
                        ),
                    }
                    task_item['awsRegion']                      = r
                    task_item['configuration']                  = task
                    if 'tags' in task:
                        task_item['tags']                       = parse_ecs_tags(task['tags'])
                    task_item['supplementaryConfiguration']     = {}
                    task_item[
                        'resourceId'
                    ] = f"{task['taskDefinitionArn'].split('/')[-1]}-{target_account.account_id}"
                    task_item['resourceName']                   = task['taskDefinitionArn'].split('/')[-1]
                    task_item['ARN']                            = task['taskArn']
                    task_item['errors']                         = {}
                    save_resource_to_s3(TASK_RESOURCE_PATH, task_item['resourceId'], task_item)

    except AntiopeAssumeRoleError as e:
        logger.error(
            f"Unable to assume role into account {target_account.account_name}({target_account.account_id})"
        )
        return()
    except ClientError as e:
        logger.critical(
            f"AWS Error getting info for {target_account.account_name}: {e}"
        )
        raise
    except Exception as e:
        logger.critical(f"{e}\nMessage: {message}\nContext: {vars(context)}")
        raise


def list_tasks(ecs_client, cluster_arn):
    task_arns = []
    response = ecs_client.list_tasks(cluster=cluster_arn)
    while 'nextToken' in response:
        task_arns += response['taskArns']
        response = ecs_client.list_tasks(cluster=cluster_arn, nextToken=response['nextToken'])
    task_arns += response['taskArns']
    return(task_arns)


def list_clusters(ecs_client):
    cluster_arns = []
    response = ecs_client.list_clusters()
    while 'nextToken' in response:
        cluster_arns += response['clusterArns']
        response = ecs_client.list_clusters(nextToken=response['nextToken'])
    cluster_arns += response['clusterArns']
    return(cluster_arns)


def parse_ecs_tags(tagset):
    """Convert the tagset as returned by AWS into a normal dict of {"tagkey": "tagvalue"}"""
    return {tag['key']: tag['value'] for tag in tagset}
