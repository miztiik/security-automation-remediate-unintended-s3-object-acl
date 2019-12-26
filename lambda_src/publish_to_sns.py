# -*- coding: utf-8 -*-
"""
.. module: publish_to_sns
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
    MODULE_NAME                 = 'publish_to_sns'
    LOG_LEVEL                   = logging.INFO


def lambda_handler(event, context):

    sns_client = boto3.client('sns')
    resp = sns_client.publish(
        #You will need an existing SNS topic 
        #Check out bsihra/aws-code-samples/sns for a CloudFornation to create this
        # TopicArn='arn:aws:sns:us-east-1:123456789012:sns-topic-name',
        TopicArn=event.get('sns_topic_arn'),
        Message=json.dumps(event.get('sns_message')),
        Subject=event.get('sns_subject')
    )
    logger.info(resp)
    return resp
