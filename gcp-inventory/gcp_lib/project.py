
import boto3
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key
import json
import os
import logging
import datetime
from dateutil import tz
from pprint import pprint

import logging
logger = logging.getLogger()


class GCPProject(object):
    """Class to represent a GCP Project """
    def __init__(self, projectId, project_table=None):
        '''
            Takes an projectId as the lookup attribute
        '''
        # Execute any parent class init()
        super(GCPProject, self).__init__()

        self.projectId = projectId

        # # Save these as attributes
        self.dynamodb      = boto3.resource('dynamodb')
        if project_table is None:
            project_table = os.environ['PROJECT_TABLE']
        self.project_table = self.dynamodb.Table(project_table)

        response = self.project_table.query(
            KeyConditionExpression=Key('projectId').eq(self.projectId),
            Select='ALL_ATTRIBUTES'
        )
        try:
            self.json_data = response['Items'][0]
            # Convert the response into instance attributes
            self.__dict__.update(self.json_data)
        except IndexError as e:
            raise ProjectLookupError(f"ID {projectId} not found")
        except Exception as e:
            logger.error(f"Got Other error: {e}")

    def __str__(self):
        """when converted to a string, become the projectId"""
        return(self.projectId)

    def __repr__(self):
        '''Create a useful string for this class if referenced'''
        return f"<Antiope.GCPProject {self.projectId} >"

    #
    # Database functions
    #
    def update_attribute(self, table_name, key, value):
        '''    update a specific attribute in a specific table for this project
            table_name should be a valid DynDB table, key is the column, value is the new value to set
        '''
        logger.info(f"Adding key:{key} value:{value} to project {self}")
        table = self.dynamodb.Table(table_name)
        try:
            response = table.update_item(
                Key= {
                    'projectId': self.projectId
                },
                UpdateExpression="set #k = :r",
                ExpressionAttributeNames={
                    '#k': key
                },
                ExpressionAttributeValues={
                    ':r': value,
                }
            )
        except ClientError as e:
            raise ProjectUpdateError(
                f"Failed to update {key} to {value} in {table_name}: {e}"
            )

    def get_attribute(self, table_name, key):
        '''
        Pulls a attribute from the specificed table for the project
        '''
        logger.info(f"Getting key:{key} from:{table_name} for project {self}")
        table = self.dynamodb.Table(table_name)
        try:
            response = table.get_item(
                Key= {
                    'projectId': self.projectId
                },
                AttributesToGet=[key]
            )
            return(response['Item'][key])
        except ClientError as e:
            raise ProjectLookupError(
                f"Failed to get {key} from {table_name} in {self}: {e}"
            )
        except KeyError as e:
            raise ProjectLookupError(
                f"Failed to get {key} from {table_name} in {self}: {e}"
            )

    def delete_attribute(self, table_name, key):
        '''
        Pulls a attribute from the specificed table for the project
        '''
        logger.info(f"Deleting key:{key} from:{table_name} for project {self}")
        table = self.dynamodb.Table(table_name)
        try:
            response = table.update_item(
                Key= {
                    'projectId': self.projectId
                },
                UpdateExpression="remove #k",
                ExpressionAttributeNames={
                    '#k': key
                },
                # ExpressionAttributeValues={
                # ':r': value,
                # }
            )
        except ClientError as e:
            raise ProjectLookupError(
                f"Failed to get {key} from {table_name} in {self}: {e}"
            )
        except KeyError as e:
            raise ProjectLookupError(
                f"Failed to get {key} from {table_name} in {self}: {e}"
            )


class ProjectUpdateError(Exception):
    '''raised when an update to DynamoDB Fails'''


class ProjectLookupError(LookupError):
    '''Raised when the Project requested is not in the database'''
