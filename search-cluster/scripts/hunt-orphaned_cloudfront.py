#!/usr/bin/env python3

import boto3
from botocore.exceptions import ClientError
import re
import requests
from requests_aws4auth import AWS4Auth
from elasticsearch import Elasticsearch, RequestsHttpConnection


import json
import os
import time
import datetime
from dateutil import tz

import logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)
logging.getLogger('elasticsearch').setLevel(logging.WARNING)


# Lambda execution starts here
def main(args, logger):

    region = os.environ['AWS_DEFAULT_REGION']
    service = 'es'
    credentials = boto3.Session().get_credentials()
    awsauth = AWS4Auth(credentials.access_key, credentials.secret_key, region, service, session_token=credentials.token)

    # host = "https://{}".format(os.environ['ES_DOMAIN_ENDPOINT'])
    host = get_endpoint(args.domain)

    if host is None:
        logger.error(f"Unable to find ES Endpoint for {args.domain}. Aborting....")
        exit(1)


    es = Elasticsearch(
        hosts=[{'host': host, 'port': 443}],
        http_auth=awsauth,
        use_ssl=True,
        verify_certs=True,
        connection_class=RequestsHttpConnection
    )
    if args.debug:
        logger.info(es.info())

    print("Getting list of all known buckets")
    index_name = "resources_s3_bucket"
    query = {"match_all": {}}
    res = es.search(index=index_name, size=10000, body={"query": query})
    known_buckets = [
        hit['_source']['configuration']['Name'] for hit in res['hits']['hits']
    ]
    print("Analying CloudFront Distributions and identifying all s3 buckets ownership")
    index_name = "resources_cloudfront_distribution"

    query = {
        "query_string": {
                "query": "configuration.Origins.Items.DomainName.keyword: *s3*"
            }
    }

    res = es.search(index=index_name, size=10000, body={"query": query})

    bad_count = 0
    escalate_count = 0

    s3_suffix = [ ".s3.amazonaws.com", "s3.us-west-2.amazonaws.com"]

    for hit in res['hits']['hits']:
        if args.inspect:
            print(json.dumps(hit, sort_keys=True, default=str, indent=2))
        doc = hit['_source']

        for origin in doc['configuration']['Origins']['Items']:
            if "s3" not in origin['DomainName']:
                continue

            bucket_name = extract_bucket(origin['DomainName'])

            if bucket_name not in known_buckets:
                bad_count += 1
                # print(bucket_name)

                if does_bucket_exist(bucket_name):
                    status = "Claimed by someone else"
                    escalate_count +=1
                else:
                    status = "Unclaimed"

                if 'Items' in doc['configuration']['Aliases']:
                    print(f"\t{doc['awsAccountName']} ({doc['awsAccountId']}) {doc['configuration']['DomainName']} - Bucket Name: {bucket_name} - Status: {status} - Aliased as: {doc['configuration']['Aliases']['Items']}")
                else:
                    print(f"\t{doc['awsAccountName']} ({doc['awsAccountId']}) {doc['configuration']['DomainName']} - Bucket Name: {bucket_name} - Status: {status} - No Aliases")

    print(f"Found {res['hits']['total']} Distributions. {bad_count} are potentially bad. {escalate_count} need to be treated as a security incident")

    exit(0)


def extract_bucket(endpoint):
    # See this nnightmare of possible endpoints - https://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region
    bucket_name = re.sub(r'.s3-website.+amazonaws.com', "", endpoint)
    bucket_name = re.sub(r'.s3.+amazonaws.com', "", bucket_name)
    return(bucket_name)

def does_bucket_exist(bucket_name):
    try:
        client = boto3.client('s3')
        response = client.get_bucket_location(
            Bucket=bucket_name
        )
        return(True)
    except ClientError as e:
        return e.response['Error']['Code'] != 'NoSuchBucket'


def get_endpoint(domain):
    ''' using the boto3 api, gets the URL endpoint for the cluster '''
    es_client = boto3.client('es')

    response = es_client.describe_elasticsearch_domain(DomainName=domain)
    if 'DomainStatus' in response and 'Endpoint' in response['DomainStatus']:
        return(response['DomainStatus']['Endpoint'])

    logger.error(f"Unable to get ES Endpoint for {domain}")
    return(None)

if __name__ == '__main__':

    # Process Arguments
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", help="print debugging info", action='store_true')
    parser.add_argument("--error", help="print error info only", action='store_true')
    parser.add_argument("--inspect", help="inspect the json elements for the results", action='store_true')
    parser.add_argument("--domain", help="Elastic Search Domain", required=True)

    args = parser.parse_args()

    # Logging idea stolen from: https://docs.python.org/3/howto/logging.html#configuring-logging
    # create console handler and set level to debug
    ch = logging.StreamHandler()
    if args.debug:
        ch.setLevel(logging.DEBUG)
        logging.getLogger('elasticsearch').setLevel(logging.DEBUG)
    elif args.error:
        ch.setLevel(logging.ERROR)
    else:
        ch.setLevel(logging.INFO)
    # create formatter
    # formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
    # add formatter to ch
    ch.setFormatter(formatter)
    # add ch to logger
    logger.addHandler(ch)

    # Wrap in a handler for Ctrl-C
    try:
        rc = main(args, logger)
        print(f"Lambda executed with {rc}")
    except KeyboardInterrupt:
        exit(1)
