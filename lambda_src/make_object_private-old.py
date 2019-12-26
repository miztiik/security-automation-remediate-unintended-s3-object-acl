# -*- coding: utf-8 -*-
"""
.. module: make_object_private.py
    :Actions: if object ACL is public, makes them private
    :copyright: (c) 2020 Mystique.,
.. moduleauthor:: Mystique
.. contactauthor:: miztiik@github issues
"""

import json
import logging

import boto3
from botocore.exceptions import ClientError

__author__      = 'Mystique'
__email__       = 'miztiik@github'
__version__     = '0.0.1'
__status__      = 'production'


class global_args:
    """
    Global statics
    """
    OWNER                       = 'Mystique'
    ENVIRONMENT                 = 'production'
    MODULE_NAME                 = 'make_object_private.py'
    LOG_LEVEL                   = logging.INFO


def set_logging(lv=global_args.LOG_LEVEL):
    '''
    Helper to enable logging
    '''
    logging.basicConfig(level=lv)
    logger = logging.getLogger()
    logger.setLevel(lv)
    return logger

# Initialize Logger
logger = set_logging(logging.INFO)

############### END OF HELPERS ###############

def is_obj_private(bucket_name, obj_key):
    """
    Check if the obj in a bucket is private
    """
    # Default assume object is private
    resp = {'status': False, 'is_private':True}
    client = boto3.client('s3')
    try:
        obj_acl = client.get_object_acl(Bucket=bucket_name, Key=obj_key)

        # Private object should have only one grant which is the owner of the object
        if (len(obj_acl['Grants']) > 1):
            resp['is_private'] = False

        # If canonical owner & grantee ids do no match, conclude object is NOT private
        owner_id = obj_acl['Owner']['ID']
        grantee_id = obj_acl['Grants'][0]['Grantee']['ID']
        if (owner_id != grantee_id):
            resp['is_private'] = False
        resp['status'] = True
    except ClientError as e:
        logger.error("Unable to get object:{obj_key} ACL")
        logger.error(f"ERROR:{str(e)}")
        resp['error_message'] = str(e)
    return resp


def make_obj_private(bucket_name, obj_key):
    """
    Make object in bucket private
    """
    resp = {'status': False}
    client = boto3.client('s3')
    try:
        m_resp = client.put_object_acl(Bucket=bucket_name, Key=obj_key, ACL="private")
        logger.info(f"Object:{obj_key} in Bucket:{bucket_name} is marked private")
        if m_resp['ResponseMetadata']['HTTPStatusCode'] == 200:
            resp['status'] = True
            resp['acl_remediated'] = True
    except ClientError as e:
        logger.error("Unable to mark object:{obj_key} private")
        logger.error(f"ERROR:{str(e)}")
        resp['error_message'] = str(e)
    return resp


def lambda_handler(event, context):
    """
    # For PutObjectAcl or PutObject Event, get the bucket and key event
    # If the object is not private, make it private
    """
    logger.info(f'Event:{event}')
    resp = {'status': False}
    EVENT_TYPE = 'PutObjectAcl'
    # Match Event Type
    if 'detail' in event and 'eventName' in event.get('detail'):
        if event.get('detail').get('eventName') == 'PutObjectAcl' or event.get('detail').get('eventName') == 'PutObject':
            bucket_name = event.get('detail').get('requestParameters').get('bucketName')
            obj_key = event['detail']['requestParameters']['key']
            resp['bucket_name'] = bucket_name
            resp['obj_key'] = obj_key

    p_resp = is_obj_private(bucket_name, obj_key)
    resp['is_private'] = p_resp.get('is_private')

    if p_resp.get('status') and p_resp.get('is_private'):
        logger.info(f"Object:{obj_key} in Bucket:{bucket_name} is private")

    if p_resp.get('status') and not p_resp.get('is_private'):
        logger.info(f"Object:{obj_key} in Bucket:{bucket_name} is NOT private")
        resp['acl_remediation_resp'] = make_obj_private(bucket_name, obj_key)

    if not p_resp.get('status') and not p_resp.get('is_private'):
        logger.error(f"ERROR:{p_resp.get('error_message')}")
        resp['error_message'] = p_resp.get('error_message')
    return resp

if __name__ == '__main__':
    lambda_handler({}, {})
