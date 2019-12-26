import json

from aws_cdk import aws_cloudtrail as _cloudtrail
from aws_cdk import aws_events as _events
from aws_cdk import aws_events_targets as _targets
from aws_cdk import aws_iam as _iam
from aws_cdk import aws_lambda as _lambda
from aws_cdk import aws_s3 as _s3
from aws_cdk import aws_sns as _sns
from aws_cdk import aws_sns_subscriptions as _subs
from aws_cdk import aws_stepfunctions as _sfn
from aws_cdk import aws_stepfunctions_tasks as _tasks
from aws_cdk import core


class global_args:
    '''
    Helper to define global statics
    '''
    OWNER                       = "MystiqueInfoSecurity"
    ENVIRONMENT                 = "production"
    SOURCE_INFO                 = "https://github.com/miztiik/security-automation-remediate_unintended_s3_object_acl"
    INFO_SEC_OPS_EMAIL          = "INFOSECOPS@EMAIL.COM"

class SecurityAutomationRemediateUnintendedS3ObjectAclStack(core.Stack):

    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # The code that defines your stack goes here
        pvt_bkt = _s3.Bucket(self, "s3bucket")
        core.Tag.add(pvt_bkt,key="isMonitoredBucket",value="True")


        # Lets create a cloudtrail to track s3 data events
        s3_data_event_trail = _cloudtrail.Trail(
            self,
            "s3DataEventTrailId",
            is_multi_region_trail=False,
            include_global_service_events=False,
            enable_file_validation=True
            )


        # Lets capture S3 Data Events only for our bucket- TO REDUCE COST
        s3_data_event_trail.add_s3_event_selector(
            prefixes=[
                f"{pvt_bkt.bucket_arn}/"
            ],
            include_management_events=True,
            read_write_type=_cloudtrail.ReadWriteType.ALL
            )


        # Defines an AWS Lambda resource
        """
        with open("lambda_src/make_object_private.py", encoding="utf8") as fp:
            make_object_private_fn_handler_code = fp.read()

        remediate_object_acl_fn = _lambda.Function(
            self,
            id='remediateObjAclFn',
            function_name="remediate_object_acl_fn",
            runtime=_lambda.Runtime.PYTHON_3_7,
            code=_lambda.InlineCode(make_object_private_fn_handler_code),
            handler='index.lambda_handler',
            timeout=core.Duration.seconds(10)
            )

        # Lets add the necessary permission for the lambda function
        remediate_object_acl_fn_perms=_iam.PolicyStatement(
            effect=_iam.Effect.ALLOW,
            resources=[
                "arn:aws:s3:::*",
                ],
            actions=[
                "s3:GetObjectAcl",
                "s3:PutObjectAcl"
            ]
            )
        remediate_object_acl_fn_perms.sid="PutBucketPolicy"
        remediate_object_acl_fn.add_to_role_policy( remediate_object_acl_fn_perms )
        """

        with open("lambda_src/is_object_private.py", encoding="utf8") as fp:
            is_object_private_fn_handler_code = fp.read()

        is_object_private_fn = _lambda.Function(
            self,
            id='isObjPrivateFn',
            function_name="is_object_private_fn",
            runtime=_lambda.Runtime.PYTHON_3_7,
            code=_lambda.InlineCode(is_object_private_fn_handler_code),
            handler='index.lambda_handler',
            timeout=core.Duration.seconds(3)
            )

        # Lets add the necessary permission for the lambda function
        is_object_private_fn_perms=_iam.PolicyStatement(
            effect=_iam.Effect.ALLOW,
            resources=[
                "arn:aws:s3:::*",
                ],
            actions=[
                "s3:GetObjectAcl"
            ]
            )
        is_object_private_fn.sid="CheckObjectAcl"
        is_object_private_fn.add_to_role_policy( is_object_private_fn_perms )

        with open("lambda_src/make_object_private.py", encoding="utf8") as fp:
            make_object_private_fn_handler_code = fp.read()

        remediate_object_acl_fn = _lambda.Function(
            self,
            id='remediateObjAclFn',
            function_name="remediate_object_acl_fn",
            runtime=_lambda.Runtime.PYTHON_3_7,
            code=_lambda.InlineCode(make_object_private_fn_handler_code),
            handler='index.lambda_handler',
            timeout=core.Duration.seconds(10)
            )

        # Lets add the necessary permission for the lambda function
        remediate_object_acl_fn_perms=_iam.PolicyStatement(
            effect=_iam.Effect.ALLOW,
            resources=[
                "arn:aws:s3:::*",
                ],
            actions=[
                "s3:PutObjectAcl"
            ]
            )
        remediate_object_acl_fn_perms.sid="PutObjectAcl"
        remediate_object_acl_fn.add_to_role_policy( remediate_object_acl_fn_perms )


        info_sec_ops_topic = _sns.Topic(self, "infoSecOpsTopicId",
            display_name="InfoSecTopic",
            topic_name="InfoSecOpsTopic"
        )

        # Subscribe InfoSecOps Email to topic
        info_sec_ops_topic.add_subscription(_subs.EmailSubscription(global_args.INFO_SEC_OPS_EMAIL))

        # Grant Lambda permission to publish to topic
        # info_sec_ops_topic.grant_publish(lambda_notifier)

        # State Machine for notifying failed ACLs
        # Ref: https://docs.aws.amazon.com/cdk/api/latest/docs/aws-stepfunctions-readme.html
        ###############################################################################
        ################# STEP FUNCTIONS EXPERIMENTAL CODE - UNSTABLE #################
        ###############################################################################

        is_object_private_task = _sfn.Task(self, "isObjectPrivate?",
            task=_tasks.InvokeFunction(is_object_private_fn),
            result_path="$",
            output_path="$"
            )
        
        remediate_object_acl_task = _sfn.Task(self, "RemediateObjectAcl",
            task=_tasks.InvokeFunction(remediate_object_acl_fn),
            result_path="$",
            output_path="$"
            )

        notify_secops_task = _sfn.Task(self, "Notify InfoSecOps",
            task=_tasks.PublishToTopic(info_sec_ops_topic,
                integration_pattern=_sfn.ServiceIntegrationPattern.FIRE_AND_FORGET,
                message=_sfn.TaskInput.from_data_at("$.sns_message"),
                subject="Object Acl Remediation"
                )
            )

        acl_remediation_failed_task = _sfn.Fail(self, "Acl Remediation Failed",
            cause="Acl Remediation Failed",
            error="Check Logs"
        )

        acl_compliant_task = _sfn.Succeed(self, "Object Acl Compliant",
            comment="Object Acl is Compliant"
        )

        remediate_object_acl_sfn_definition = is_object_private_task\
            .next(_sfn.Choice(self, "Is Object Private?")\
                .when(_sfn.Condition.boolean_equals("$.is_private", True), acl_compliant_task)\
                .when(_sfn.Condition.boolean_equals("$.is_private", False), remediate_object_acl_task\
                    .next(_sfn.Choice(self, "Object Remediation Complete?")\
                        .when(_sfn.Condition.boolean_equals("$.status", True),acl_compliant_task)\
                        .when(_sfn.Condition.boolean_equals("$.status", False), notify_secops_task.next(acl_remediation_failed_task))\
                        .otherwise(acl_remediation_failed_task)\
                        )
                    )
                .otherwise(acl_remediation_failed_task)
            )

        remediate_object_acl_statemachine = _sfn.StateMachine(self, "stateMachineId",
                definition=remediate_object_acl_sfn_definition,
                timeout=core.Duration.minutes(3)
            )


        # Cloudwatch Event Triggers
        put_object_acl_event_targets = []
        """
        put_object_acl_event_targets.append(
            _targets.LambdaFunction( 
                handler=remediate_object_acl_fn
                )
            )
        """
        put_object_acl_event_targets.append(
            _targets.SfnStateMachine( 
                machine=remediate_object_acl_statemachine
            )
            )

        put_object_acl_event_pattern = _events.EventPattern(
                source=["aws.s3"],
                detail_type=["AWS API Call via CloudTrail"],
                detail={
                    "eventSource": [
                    "s3.amazonaws.com"
                    ],
                    "eventName": [
                        "PutObjectAcl",
                        "PutObject"
                    ],
                    "requestParameters": {
                       "bucketName": [
                            f"{pvt_bkt.bucket_name}"
                        ]
                    }
                }
            )

        put_object_acl_event_pattern_rule = _events.Rule(self,
            "putObjectAclEventId",
            event_pattern = put_object_acl_event_pattern,
            rule_name = f"put_s3_policy_event_{global_args.OWNER}",
            enabled = True,
            description = "Trigger an event for S3 PutObjectAcl or PutObject",
            targets = put_object_acl_event_targets
            )

        ###########################################
        ################# OUTPUTS #################
        ###########################################

        output0 = core.CfnOutput(self,
            "SecuirtyAutomationFrom",
            value=f"{global_args.SOURCE_INFO}",
            description="To know more about this automation stack, check out our github page."
            )

        output1 = core.CfnOutput(self,
            "MonitoredS3Bucket",
            value=(
                    f"https://console.aws.amazon.com/s3/buckets/"
                    f"{pvt_bkt.bucket_name}"
                ),
            description=f"S3 Bucket for testing purposes"
            )

        output2 = core.CfnOutput(self,
            "Helpercommands",
            value=(
                    f"aws s3api get-object-acl  --bucket ${pvt_bkt.bucket_name} --key OBJECT-KEY-NAME"
                ),
            description=f"Commands to set object to public, Update OBJECT-KEY-NAME to your needs"
            )
