
import boto3
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key
import json
import os
import logging
import datetime
from dateutil import tz
from pprint import pprint

logger = logging.getLogger()

class AzureSubscription(object):
    """Class to represent a Azure Subscription """
    def __init__(self, subscription_id):
        '''
            Takes an subsription_id as the lookup attribute
        '''
        # Execute any parent class init()

        self.subscription_id = subscription_id

        # # Save these as attributes
        self.dynamodb = boto3.resource('dynamodb')
        self.subscription_table = self.dynamodb.Table(os.environ['SUBSCRIPTION_TABLE'])

        response = self.subscription_table.query(
            KeyConditionExpression=Key('subscription_id').eq(self.subscription_id),
            Select='ALL_ATTRIBUTES'
        )
        try:
            item = response['Items'][0]
            # Convert the response into instance attributes
            self.__dict__.update(item)
        except IndexError as e:
            raise SubscriptionLookupError(f"ID {subscription_id} not found")
        except Exception as e:
            logger.error(f"Got Other error: {e}")

    def __str__(self):
        """when converted to a string, become the subscription_id"""
        return(self.subscription_id)

    def __repr__(self):
        '''Create a useful string for this class if referenced'''
        return f"<Antiope.AzureSubscription {self.subscription_id} >"


    #
    # Database functions
    #

    def update_attribute(self, table_name, key, value):
        '''    update a specific attribute in a specific table for this subscription
            table_name should be a valid DynDB table, key is the column, value is the new value to set
        '''
        logger.info(f"Adding key:{key} value:{value} to subscription {self}")
        table = self.dynamodb.Table(table_name)
        try:
            response = table.update_item(
                Key= {
                    'subscription_id': self.subscription_id
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
            raise SubscriptionUpdateError(
                f"Failed to update {key} to {value} in {table_name}: {e}"
            )

    def get_attribute(self, table_name, key):
        '''
        Pulls a attribute from the specificed table for the subscription
        '''
        logger.info(f"Getting key:{key} from:{table_name} for subscription {self}")
        table = self.dynamodb.Table(table_name)
        try:
            response = table.get_item(
                Key= {
                    'subscription_id': self.subscription_id
                },
                AttributesToGet=[ key ]
            )
            return(response['Item'][key])
        except ClientError as e:
            raise SubscriptionLookupError(
                f"Failed to get {key} from {table_name} in {self}: {e}"
            )
        except KeyError as e:
            raise SubscriptionLookupError(
                f"Failed to get {key} from {table_name} in {self}: {e}"
            )

    def delete_attribute(self, table_name, key):
        '''
        Pulls a attribute from the specificed table for the subscription
        '''
        logger.info(f"Deleting key:{key} from:{table_name} for subscription {self}")
        table = self.dynamodb.Table(table_name)
        try:
            response = table.update_item(
                Key= {
                    'subscription_id': self.subscription_id
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
            raise SubscriptionLookupError(
                f"Failed to get {key} from {table_name} in {self}: {e}"
            )
        except KeyError as e:
            raise SubscriptionLookupError(
                f"Failed to get {key} from {table_name} in {self}: {e}"
            )


class AssumeRoleError(Exception):
    '''raised when the AssumeRole Fails'''

class SubscriptionUpdateError(Exception):
    '''raised when an update to DynamoDB Fails'''

class SubscriptionLookupError(LookupError):
    '''Raised when the Subscription requested is not in the database'''
