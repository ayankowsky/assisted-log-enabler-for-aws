# // Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# // SPDX-License-Identifier: Apache-2.0
# Assisted Log Enabler for AWS - Find resources that are not logging, and turn them on.
# Joshua "DozerCat" McKiddy - Customer Incident Response Team (CIRT) - AWS


import datetime
import json
import logging
import os
import json
import random
import string
from datetime import timezone

import boto3
import boto3.session

current_date = datetime.datetime.now(tz=timezone.utc)
current_date_string = str(current_date)
timestamp_date = datetime.datetime.now(tz=timezone.utc).strftime("%Y-%m-%d-%H%M%S")
timestamp_date_string = str(timestamp_date)


sts = boto3.client("sts")
s3 = boto3.client("s3")
cloudtrail = boto3.client("cloudtrail")
organizations = boto3.client("organizations")
region = os.environ["AWS_REGION"]


# Get partition
def get_partition():
    session = boto3.session.Session()
    return session.get_partition_for_region(region)


# Get region list based on partition
def get_region_list(partition):
    region_list = []

    # Commercial regions
    if partition == "aws":
        acct_client = boto3.client("account")
        response = acct_client.list_regions(
            RegionOptStatusContains=[
                "ENABLED",
                "ENABLED_BY_DEFAULT",
            ]
        )

        for region in response["Regions"]:
            region_list.append(region["RegionName"])
    # GovCloud regions
    if partition == "aws-us-gov":
        region_list = [
            "us-gov-west-1",
            "us-gov-east-1",
        ]

    return region_list


# Define random string for newly created S3 buckets
def random_string_generator():
    lower_letters = string.ascii_lowercase
    numbers = string.digits
    unique_end = "".join(random.choice(lower_letters + numbers) for char in range(6))
    return unique_end


# Obtain the AWS Accounts inside of AWS Organizations
def org_account_grab():
    """Function to list accounts inside of AWS Organizations"""
    try:
        OrgAccountIdList: list = []
        org_account_list = organizations.list_accounts()
        for accounts in org_account_list["Accounts"]:
            OrgAccountIdList.append(accounts["Id"])
        get_organization_id = organizations.describe_organization()
        organization_id = get_organization_id["Organization"]["Id"]
    except Exception as exception_handle:
        logging.error(exception_handle)
        logging.error(
            "Multi account mode is only for accounts using AWS Organizations."
        )
        logging.error(
            "Please run the Assisted Log Enabler in single account mode to turn on AWS Logs."
        )
        exit()
    return OrgAccountIdList, organization_id


# Obtain the current AWS Account Number
def get_account_number():
    """Function to grab AWS Account number that Assisted Log Enabler runs from."""
    sts = boto3.client("sts")
    account_number = sts.get_caller_identity()["Account"]
    return account_number


# Returns string of the JSON bucket policy
def get_bucket_policy(
    bucket_name, account_number, account_id_list, ale_role_list, partition
):
    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck20150319",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:{partition}:s3:::{bucket_name}",
            },
            {
                "Sid": "AWSCloudTrailWrite20150319",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:{partition}:s3:::{bucket_name}/cloudtrail/AWSLogs/{account_number}/*",
                "Condition": {
                    "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
                },
            },
            {
                "Sid": "AWSLogDeliveryAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "delivery.logs.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:{partition}:s3:::{bucket_name}",
            },
            {
                "Sid": "AWSLogDeliveryWriteVPC",
                "Effect": "Allow",
                "Principal": {"Service": "delivery.logs.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:{partition}:s3:::{bucket_name}/vpcflowlogs/*",
                "Condition": {
                    "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
                },
            },
            {
                "Sid": "AWSLogDeliveryWriteR53",
                "Effect": "Allow",
                "Principal": {"Service": "delivery.logs.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:{partition}:s3:::{bucket_name}/r53querylogs/*",
                "Condition": {
                    "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
                },
            },
            {
                "Sid": "Deny non-HTTPS access",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": f"arn:{partition}:s3:::{bucket_name}/guardduty/*",
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            },
            {
                "Sid": "Allow GuardDuty Cross-Account S3 Permissions",
                "Effect": "Allow",
                "Principal": {"Service": "guardduty.amazonaws.com"},
                "Action": ["s3:PutObject", "s3:GetBucketLocation"],
                "Resource": [
                    f"arn:{partition}:s3:::{bucket_name}",
                    f"arn:{partition}:s3:::{bucket_name}/guardduty/*",
                ],
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id_list}},
            },
            {
                "Sid": "Allow ALE Role to bucket",
                "Effect": "Allow",
                "Principal": {"AWS": ale_role_list},
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [
                    f"arn:{partition}:s3:::{bucket_name}",
                    f"arn:{partition}:s3:::{bucket_name}/*",
                ],
            },
        ],
    }

    return json.dumps(bucket_policy)


# Create a Bucket and Lifecycle Policy
def create_bucket(OrgAccountIdList, account_number, unique_end, partition):
    """Function to create the bucket for storing logs"""
    try:
        logging.info("Creating bucket in %s" % account_number)
        logging.info("CreateBucket API Call")
        bucket_name = (
            "aws-log-collection-" + account_number + "-" + region + "-" + unique_end
        )
        if region == "us-east-1":
            logging_bucket_dict = s3.create_bucket(Bucket=bucket_name)
        else:
            logging_bucket_dict = s3.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={"LocationConstraint": region},
            )
        logging.info("Bucket Created.")
        logging.info("Setting lifecycle policy.")
        lifecycle_policy = s3.put_bucket_lifecycle_configuration(
            Bucket=bucket_name,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "Expiration": {"Days": 365},
                        "Status": "Enabled",
                        "Prefix": "",
                        "ID": "LogStorage",
                        "Transitions": [
                            {"Days": 90, "StorageClass": "INTELLIGENT_TIERING"}
                        ],
                    }
                ]
            },
        )
        logging.info("Lifecycle Policy successfully set.")
        s3.put_object(
            Bucket=bucket_name, Key="cloudtrail/AWSLogs/" + account_number + "/"
        )
        s3.put_object(Bucket=bucket_name, Key="vpcflowlogs/")
        s3.put_object(Bucket=bucket_name, Key="r53querylogs/")

        # Convert list of account IDs and ALE roles to JSON format
        account_id_list = json.dumps(OrgAccountIdList)
        role_list = []
        for id in OrgAccountIdList:
            role_list.append(
                f"arn:{partition}:iam::{id}:role/Assisted_Log_Enabler_IAM_Role"
            )
        ale_role_list = json.dumps(role_list)

        logging.info("PutBucketPolicy API Call")
        s3.put_bucket_policy(
            Bucket=bucket_name,
            Policy=get_bucket_policy(
                bucket_name, account_number, account_id_list, ale_role_list, partition
            ),
        )
        logging.info("Setting the S3 bucket Public Access to Blocked")
        logging.info("PutPublicAccessBlock API Call")
        bucket_private = s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
    except Exception as exception_handle:
        logging.error(exception_handle)
    return bucket_name


# If custom bucket is supplied, update the bucket policy
def update_custom_bucket_policy(
    bucket_name, account_number, OrgAccountIdList, partition
):
    # Convert list of account IDs and ALE roles to JSON format
    account_id_list = json.dumps(OrgAccountIdList)
    role_list = []
    for id in OrgAccountIdList:
        role_list.append(
            f"arn:{partition}:iam::{id}:role/Assisted_Log_Enabler_IAM_Role"
        )
    ale_role_list = json.dumps(role_list)

    logging.info("Pre-existing S3 bucket specified. Updating bucket policy.")
    logging.info("PutBucketPolicy API Call")
    s3.put_bucket_policy(
        Bucket=bucket_name,
        Policy=get_bucket_policy(
            bucket_name, account_number, account_id_list, ale_role_list, partition
        ),
    )


# Find VPCs and turn flow logs on if not on already
def flow_log_activator(
    OrgAccountIdList,
    region_list,
    bucket_name,
    included_accounts,
    excluded_accounts,
    partition,
):
    """Function to define the list of VPCs without logging turned on"""
    logging.info("Creating a list of VPCs without Flow Logs on.")
    for org_account in OrgAccountIdList:
        if excluded_accounts != "none" and org_account in excluded_accounts:
            continue
        elif included_accounts == "all" or org_account in included_accounts:
            for aws_region in region_list:
                sts = boto3.client("sts")
                RoleArn = f"arn:{partition}:iam::{org_account}:role/Assisted_Log_Enabler_IAM_Role"
                logging.info(
                    "Assuming Target Role %s for Assisted Log Enabler..." % RoleArn
                )
                assisted_log_enabler_sts = sts.assume_role(
                    RoleArn=RoleArn,
                    RoleSessionName="assisted-log-enabler-activation",
                    DurationSeconds=3600,
                )
                ec2_ma = boto3.client(
                    "ec2",
                    aws_access_key_id=assisted_log_enabler_sts["Credentials"][
                        "AccessKeyId"
                    ],
                    aws_secret_access_key=assisted_log_enabler_sts["Credentials"][
                        "SecretAccessKey"
                    ],
                    aws_session_token=assisted_log_enabler_sts["Credentials"][
                        "SessionToken"
                    ],
                    region_name=aws_region,
                )
                logging.info(
                    "Creating a list of VPCs without Flow Logs on in region "
                    + aws_region
                    + "."
                )
                try:
                    VPCList: list = []
                    FlowLogList: list = []
                    logging.info("DescribeVpcs API Call")
                    vpcs = ec2_ma.describe_vpcs()
                    for vpc_id in vpcs["Vpcs"]:
                        VPCList.append(vpc_id["VpcId"])
                    logging.info(
                        "List of VPCs found within account "
                        + org_account
                        + ", region "
                        + aws_region
                        + ":"
                    )
                    print(VPCList)
                    vpcflowloglist = ec2_ma.describe_flow_logs()
                    logging.info("DescribeFlowLogs API Call")
                    for resource_id in vpcflowloglist["FlowLogs"]:
                        FlowLogList.append(resource_id["ResourceId"])
                    working_list = list(set(VPCList) - set(FlowLogList))
                    logging.info(
                        "List of VPCs found within account "
                        + org_account
                        + ", region "
                        + aws_region
                        + " WITHOUT VPC Flow Logs:"
                    )
                    print(working_list)
                    for no_logs in working_list:
                        logging.info(
                            no_logs
                            + " does not have VPC Flow logging on. It will be turned on within this function."
                        )
                    logging.info(
                        "Activating logs for VPCs that do not have them turned on."
                    )
                    logging.info(
                        "If all VPCs have Flow Logs turned on, you will get an MissingParameter error. That is normal."
                    )
                    logging.info("CreateFlowLogs API Call")
                    flow_log_on = ec2_ma.create_flow_logs(
                        ResourceIds=working_list,
                        ResourceType="VPC",
                        TrafficType="ALL",
                        LogDestinationType="s3",
                        LogDestination=f"arn:{partition}:s3:::{bucket_name}/vpcflowlogs",
                        LogFormat="${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status} ${vpc-id} ${type} ${tcp-flags} ${subnet-id} ${sublocation-type} ${sublocation-id} ${region} ${pkt-srcaddr} ${pkt-dstaddr} ${instance-id} ${az-id} ${pkt-src-aws-service} ${pkt-dst-aws-service} ${flow-direction} ${traffic-path}",
                        TagSpecifications=[
                            {
                                "ResourceType": "vpc-flow-log",
                                "Tags": [
                                    {
                                        "Key": "workflow",
                                        "Value": "assisted-log-enabler",
                                    },
                                ],
                            }
                        ],
                    )
                    logging.info(
                        "VPC Flow Logs are turned on for account " + org_account + "."
                    )
                except Exception as exception_handle:
                    logging.error(exception_handle)


# Turn on EKS audit and authenticator logs.
def eks_logging(
    region_list, OrgAccountIdList, included_accounts, excluded_accounts, partition
):
    """Function to turn on logging for EKS Clusters"""
    for org_account in OrgAccountIdList:
        if excluded_accounts != "none" and org_account in excluded_accounts:
            continue
        elif included_accounts == "all" or org_account in included_accounts:
            for aws_region in region_list:
                logging.info(
                    "Turning on audit and authenticator logging for EKS clusters in AWS account "
                    + org_account
                    + ", in region "
                    + aws_region
                    + "."
                )
                sts = boto3.client("sts")
                RoleArn = f"arn:{partition}:iam::{org_account}:role/Assisted_Log_Enabler_IAM_Role"
                logging.info(
                    "Assuming Target Role %s for Assisted Log Enabler..." % RoleArn
                )
                assisted_log_enabler_sts = sts.assume_role(
                    RoleArn=RoleArn,
                    RoleSessionName="assisted-log-enabler-activation",
                    DurationSeconds=3600,
                )
                eks_ma = boto3.client(
                    "eks",
                    aws_access_key_id=assisted_log_enabler_sts["Credentials"][
                        "AccessKeyId"
                    ],
                    aws_secret_access_key=assisted_log_enabler_sts["Credentials"][
                        "SecretAccessKey"
                    ],
                    aws_session_token=assisted_log_enabler_sts["Credentials"][
                        "SessionToken"
                    ],
                    region_name=aws_region,
                )
                try:
                    logging.info("ListClusters API Call")
                    eks_clusters = eks_ma.list_clusters()
                    eks_cluster_list = eks_clusters["clusters"]
                    logging.info("EKS Clusters found in " + aws_region + ":")
                    print(eks_cluster_list)
                    for cluster in eks_cluster_list:
                        logging.info("UpdateClusterConfig API Call")
                        eks_activate = eks_ma.update_cluster_config(
                            name=cluster,
                            logging={
                                "clusterLogging": [
                                    {
                                        "types": [
                                            "audit",
                                        ],
                                        "enabled": True,
                                    },
                                    {
                                        "types": [
                                            "authenticator",
                                        ],
                                        "enabled": True,
                                    },
                                ]
                            },
                        )
                        if eks_activate["update"]["status"] == "InProgress":
                            logging.info(
                                cluster
                                + " EKS Cluster is currently updating. Status: InProgress"
                            )
                        elif eks_activate["update"]["status"] == "Failed":
                            logging.info(
                                cluster
                                + " EKS Cluster failed to turn on logs. Please check if you have permissions to update the logging configuration of EKS. Status: Failed"
                            )
                        elif eks_activate["update"]["status"] == "Cancelled":
                            logging.info(
                                cluster
                                + " EKS Cluster log update was cancelled. Status: Cancelled."
                            )
                        else:
                            logging.info(
                                cluster
                                + " EKS Cluster has audit and authenticator logs turned on."
                            )
                except Exception as exception_handle:
                    logging.error(exception_handle)


# Turn on Route 53 Query logging
def route_53_query_logs(
    region_list,
    OrgAccountIdList,
    bucket_name,
    included_accounts,
    excluded_accounts,
    partition,
):
    """Function to turn on Route 53 Query Logs for VPCs"""
    for org_account in OrgAccountIdList:
        if excluded_accounts != "none" and org_account in excluded_accounts:
            continue
        elif included_accounts == "all" or org_account in included_accounts:
            for aws_region in region_list:
                logging.info(
                    "Turning on Route 53 Query Logging on in AWS Account "
                    + org_account
                    + " VPCs, in region "
                    + aws_region
                    + "."
                )
                sts = boto3.client("sts")
                RoleArn = f"arn:{partition}:iam::{org_account}:role/Assisted_Log_Enabler_IAM_Role"
                logging.info(
                    "Assuming Target Role %s for Assisted Log Enabler..." % RoleArn
                )
                assisted_log_enabler_sts = sts.assume_role(
                    RoleArn=RoleArn,
                    RoleSessionName="assisted-log-enabler-activation",
                    DurationSeconds=3600,
                )
                ec2_ma = boto3.client(
                    "ec2",
                    aws_access_key_id=assisted_log_enabler_sts["Credentials"][
                        "AccessKeyId"
                    ],
                    aws_secret_access_key=assisted_log_enabler_sts["Credentials"][
                        "SecretAccessKey"
                    ],
                    aws_session_token=assisted_log_enabler_sts["Credentials"][
                        "SessionToken"
                    ],
                    region_name=aws_region,
                )
                route53resolver_ma = boto3.client(
                    "route53resolver",
                    aws_access_key_id=assisted_log_enabler_sts["Credentials"][
                        "AccessKeyId"
                    ],
                    aws_secret_access_key=assisted_log_enabler_sts["Credentials"][
                        "SecretAccessKey"
                    ],
                    aws_session_token=assisted_log_enabler_sts["Credentials"][
                        "SessionToken"
                    ],
                    region_name=aws_region,
                )
                try:
                    VPCList: list = []
                    QueryLogList: list = []
                    logging.info("DescribeVpcs API Call")
                    vpcs = ec2_ma.describe_vpcs()
                    for vpc_id in vpcs["Vpcs"]:
                        VPCList.append(vpc_id["VpcId"])
                    logging.info(
                        "List of VPCs found within account "
                        + org_account
                        + ", region "
                        + aws_region
                        + ":"
                    )
                    print(VPCList)
                    logging.info("ListResolverQueryLogConfigAssociations API Call")
                    query_log_details = (
                        route53resolver_ma.list_resolver_query_log_config_associations()
                    )
                    for query_log_vpc_id in query_log_details[
                        "ResolverQueryLogConfigAssociations"
                    ]:
                        QueryLogList.append(query_log_vpc_id["ResourceId"])
                    r53_working_list = list(set(VPCList) - set(QueryLogList))
                    logging.info(
                        "List of VPCs found within account "
                        + org_account
                        + ", region "
                        + aws_region
                        + " WITHOUT Route 53 Query Logs:"
                    )
                    print(r53_working_list)
                    for no_query_logs in r53_working_list:
                        logging.info(
                            no_query_logs
                            + " does not have Route 53 Query logging on. It will be turned on within this function."
                        )
                    logging.info(
                        "Activating logs for VPCs that do not have Route 53 Query logging turned on."
                    )
                    logging.info("CreateResolverQueryLogConfig API Call")
                    create_query_log = route53resolver_ma.create_resolver_query_log_config(
                        Name="Assisted_Log_Enabler_Query_Logs_" + aws_region,
                        DestinationArn=f"arn:{partition}:s3:::{bucket_name}/r53querylogs",
                        CreatorRequestId=timestamp_date_string,
                        Tags=[
                            {"Key": "Workflow", "Value": "assisted-log-enabler"},
                        ],
                    )
                    r53_query_log_id = create_query_log["ResolverQueryLogConfig"]["Id"]
                    logging.info(
                        "Route 53 Query Logging Created. Resource ID:"
                        + r53_query_log_id
                    )
                    for vpc in r53_working_list:
                        logging.info(
                            "Associating "
                            + vpc
                            + " with the created Route 53 Query Logging."
                        )
                        logging.info("AssocateResolverQueryLogConfig")
                        activate_r5_logs = (
                            route53resolver_ma.associate_resolver_query_log_config(
                                ResolverQueryLogConfigId=r53_query_log_id,
                                ResourceId=vpc,
                            )
                        )
                except Exception as exception_handle:
                    logging.error(exception_handle)


# Turn on S3 access logging
def s3_logs(
    region_list,
    OrgAccountIdList,
    unique_end,
    included_accounts,
    excluded_accounts,
    partition,
):
    """Function to turn on Bucket Logs for Buckets"""
    for org_account in OrgAccountIdList:
        if excluded_accounts != "none" and org_account in excluded_accounts:
            continue
        elif included_accounts == "all" or org_account in included_accounts:
            for aws_region in region_list:
                logging.info(
                    "Turning on Bucket Logging on in AWS Account "
                    + org_account
                    + " Buckets, in region "
                    + aws_region
                    + "."
                )
                sts = boto3.client("sts")
                RoleArn = f"arn:{partition}:iam::{org_account}:role/Assisted_Log_Enabler_IAM_Role"
                logging.info(
                    "Assuming Target Role %s for Assisted Log Enabler..." % RoleArn
                )
                assisted_log_enabler_sts = sts.assume_role(
                    RoleArn=RoleArn,
                    RoleSessionName="assisted-log-enabler-activation",
                    DurationSeconds=3600,
                )
                s3_ma = boto3.client(
                    "s3",
                    aws_access_key_id=assisted_log_enabler_sts["Credentials"][
                        "AccessKeyId"
                    ],
                    aws_secret_access_key=assisted_log_enabler_sts["Credentials"][
                        "SecretAccessKey"
                    ],
                    aws_session_token=assisted_log_enabler_sts["Credentials"][
                        "SessionToken"
                    ],
                    region_name=aws_region,
                )
                try:
                    S3List: list = []
                    S3LogList: list = []
                    logging.info("ListBuckets API Call")
                    buckets = s3_ma.list_buckets()
                    for bucket in buckets["Buckets"]:
                        s3region = s3_ma.get_bucket_location(Bucket=bucket["Name"])[
                            "LocationConstraint"
                        ]
                        if s3region == aws_region:
                            S3List.append(bucket["Name"])
                        elif s3region is None and aws_region == "us-east-1":
                            S3List.append(bucket["Name"])
                    if S3List != []:
                        logging.info(
                            "List of Buckets found within account "
                            + org_account
                            + ", region "
                            + aws_region
                            + ":"
                        )
                        print(S3List)
                        logging.info(
                            "Parsed out buckets created by Assisted Log Enabler for AWS in "
                            + aws_region
                        )
                        logging.info(
                            "Checking remaining buckets to see if logs were enabled by Assisted Log Enabler for AWS in "
                            + aws_region
                        )
                        logging.info("GetBucketLogging API Call")
                        for bucket in S3List:
                            if (
                                "aws-s3-log-collection-"
                                + org_account
                                + "-"
                                + aws_region
                                not in str(bucket)
                            ):
                                s3temp = s3_ma.get_bucket_logging(Bucket=bucket)
                                if "TargetBucket" not in str(s3temp):
                                    S3LogList.append(bucket)
                        if S3LogList != []:
                            logging.info(
                                "List of Buckets found within account "
                                + org_account
                                + ", region "
                                + aws_region
                                + " WITHOUT S3 Bucket Logs:"
                            )
                            print(S3LogList)
                            for bucket in S3LogList:
                                logging.info(
                                    bucket
                                    + " does not have S3 BUCKET logging on. It will be turned on within this function."
                                )
                            logging.info("Creating S3 Logging Bucket")
                            account_number = sts.get_caller_identity()["Account"]
                            logging.info("Creating bucket in %s" % org_account)
                            logging.info("CreateBucket API Call")
                            if aws_region == "us-east-1":
                                logging_bucket_dict = s3_ma.create_bucket(
                                    Bucket="aws-s3-log-collection-"
                                    + org_account
                                    + "-"
                                    + aws_region
                                    + "-"
                                    + unique_end
                                )
                            else:
                                logging_bucket_dict = s3_ma.create_bucket(
                                    Bucket="aws-s3-log-collection-"
                                    + org_account
                                    + "-"
                                    + aws_region
                                    + "-"
                                    + unique_end,
                                    CreateBucketConfiguration={
                                        "LocationConstraint": aws_region
                                    },
                                )
                            logging.info(
                                "Bucket "
                                + "aws-s3-log-collection-"
                                + org_account
                                + "-"
                                + aws_region
                                + "-"
                                + unique_end
                                + " Created."
                            )
                            logging.info("Setting lifecycle policy.")
                            logging.info("PutBucketLifecycleConfiguration API Call")
                            lifecycle_policy = s3_ma.put_bucket_lifecycle_configuration(
                                Bucket="aws-s3-log-collection-"
                                + org_account
                                + "-"
                                + aws_region
                                + "-"
                                + unique_end,
                                LifecycleConfiguration={
                                    "Rules": [
                                        {
                                            "Expiration": {"Days": 365},
                                            "Status": "Enabled",
                                            "Prefix": "",
                                            "ID": "LogStorage",
                                            "Transitions": [
                                                {
                                                    "Days": 90,
                                                    "StorageClass": "INTELLIGENT_TIERING",
                                                }
                                            ],
                                        }
                                    ]
                                },
                            )
                            logging.info("Lifecycle Policy successfully set.")
                            logging.info(
                                "Setting the S3 bucket Public Access to Blocked"
                            )
                            logging.info("PutPublicAccessBlock API Call")
                            bucket_private = s3_ma.put_public_access_block(
                                Bucket="aws-s3-log-collection-"
                                + org_account
                                + "-"
                                + aws_region
                                + "-"
                                + unique_end,
                                PublicAccessBlockConfiguration={
                                    "BlockPublicAcls": True,
                                    "IgnorePublicAcls": True,
                                    "BlockPublicPolicy": True,
                                    "RestrictPublicBuckets": True,
                                },
                            )
                            logging.info("GetBucketAcl API Call")
                            id = s3_ma.get_bucket_acl(
                                Bucket="aws-s3-log-collection-"
                                + org_account
                                + "-"
                                + aws_region
                                + "-"
                                + unique_end
                            )["Owner"]["ID"]
                            logging.info("PutBucketAcl API Call")
                            s3_ma.put_bucket_acl(
                                Bucket="aws-s3-log-collection-"
                                + org_account
                                + "-"
                                + aws_region
                                + "-"
                                + unique_end,
                                GrantReadACP="uri=http://acs.amazonaws.com/groups/s3/LogDelivery",
                                GrantWrite="uri=http://acs.amazonaws.com/groups/s3/LogDelivery",
                                GrantFullControl="id=" + id,
                            )
                            for bucket in S3LogList:
                                logging.info("Activating logs for S3 Bucket " + bucket)
                                logging.info("PutBucketLogging API Call")
                                create_s3_log = s3_ma.put_bucket_logging(
                                    Bucket=bucket,
                                    BucketLoggingStatus={
                                        "LoggingEnabled": {
                                            "TargetBucket": "aws-s3-log-collection-"
                                            + org_account
                                            + "-"
                                            + aws_region
                                            + "-"
                                            + unique_end,
                                            "TargetGrants": [
                                                {
                                                    "Permission": "FULL_CONTROL",
                                                    "Grantee": {
                                                        "Type": "Group",
                                                        "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery",
                                                    },
                                                },
                                            ],
                                            "TargetPrefix": "s3logs/" + bucket,
                                        }
                                    },
                                )
                        else:
                            logging.info(
                                "No S3 Bucket WITHOUT Logging enabled on account "
                                + org_account
                                + " region "
                                + aws_region
                            )
                    else:
                        logging.info(
                            "No S3 Buckets found within account "
                            + org_account
                            + ", region "
                            + aws_region
                            + ":"
                        )
                except Exception as exception_handle:
                    logging.error(exception_handle)


# Turn on Load Balancer logging
def lb_logs(
    region_list,
    OrgAccountIdList,
    unique_end,
    included_accounts,
    excluded_accounts,
    partition,
):
    """Function to turn on Load Balancer Logs"""
    for org_account in OrgAccountIdList:
        if excluded_accounts != "none" and org_account in excluded_accounts:
            continue
        elif included_accounts == "all" or org_account in included_accounts:
            for aws_region in region_list:
                logging.info(
                    "Checking for Load Balancer Logging in the account "
                    + org_account
                    + " in region "
                    + aws_region
                    + "."
                )
                sts = boto3.client("sts")
                RoleArn = f"arn:{partition}:iam::{org_account}:role/Assisted_Log_Enabler_IAM_Role"
                logging.info(
                    f"Assuming Target Role {RoleArn} for Assisted Log Enabler..."
                )
                assisted_log_enabler_sts = sts.assume_role(
                    RoleArn=RoleArn,
                    RoleSessionName="assisted-log-enabler-activation",
                    DurationSeconds=3600,
                )
                elbv1_ma = boto3.client(
                    "elb",
                    aws_access_key_id=assisted_log_enabler_sts["Credentials"][
                        "AccessKeyId"
                    ],
                    aws_secret_access_key=assisted_log_enabler_sts["Credentials"][
                        "SecretAccessKey"
                    ],
                    aws_session_token=assisted_log_enabler_sts["Credentials"][
                        "SessionToken"
                    ],
                    region_name=aws_region,
                )
                elbv2_ma = boto3.client(
                    "elbv2",
                    aws_access_key_id=assisted_log_enabler_sts["Credentials"][
                        "AccessKeyId"
                    ],
                    aws_secret_access_key=assisted_log_enabler_sts["Credentials"][
                        "SecretAccessKey"
                    ],
                    aws_session_token=assisted_log_enabler_sts["Credentials"][
                        "SessionToken"
                    ],
                    region_name=aws_region,
                )
                s3_ma = boto3.client(
                    "s3",
                    aws_access_key_id=assisted_log_enabler_sts["Credentials"][
                        "AccessKeyId"
                    ],
                    aws_secret_access_key=assisted_log_enabler_sts["Credentials"][
                        "SecretAccessKey"
                    ],
                    aws_session_token=assisted_log_enabler_sts["Credentials"][
                        "SessionToken"
                    ],
                    region_name=aws_region,
                )
                try:
                    ELBList1: list = []
                    ELBList2: list = []
                    ELBLogList: list = []
                    ELBv1LogList: list = []
                    ELBv2LogList: list = []
                    logging.info("DescribeLoadBalancers API Call")
                    ELBList1 = elbv1_ma.describe_load_balancers()
                    for lb in ELBList1["LoadBalancerDescriptions"]:
                        logging.info("DescribeLoadBalancerAttibute API Call")
                        lblog = elbv1_ma.describe_load_balancer_attributes(
                            LoadBalancerName=lb["LoadBalancerName"]
                        )
                        logging.info("Parsing out for ELB Access Logging")
                        if (
                            lblog["LoadBalancerAttributes"]["AccessLog"]["Enabled"]
                            == False
                        ):
                            ELBv1LogList.append([lb["LoadBalancerName"], "classic"])
                    logging.info("DescribeLoadBalancers v2 API Call")
                    ELBList2 = elbv2_ma.describe_load_balancers()
                    for lb in ELBList2["LoadBalancers"]:
                        logging.info("DescribeLoadBalancerAttibute v2 API Call")
                        lblog = elbv2_ma.describe_load_balancer_attributes(
                            LoadBalancerArn=lb["LoadBalancerArn"]
                        )
                        logging.info("Parsing out for ELBv2 Access Logging")
                        for lbtemp in lblog["Attributes"]:
                            if lbtemp["Key"] == "access_logs.s3.enabled":
                                if lbtemp["Value"] == "false":
                                    ELBv2LogList.append(
                                        [lb["LoadBalancerName"], lb["LoadBalancerArn"]]
                                    )
                    ELBLogList = ELBv1LogList + ELBv2LogList
                    if ELBLogList != []:
                        logging.info(
                            "List of Load Balancers found within account "
                            + org_account
                            + ", region "
                            + aws_region
                            + " without logging enabled:"
                        )
                        print(ELBLogList)
                        for elb in ELBLogList:
                            logging.info(
                                elb[0]
                                + " does not have Load Balancer logging on. It will be turned on within this function."
                            )
                        logging.info("Creating S3 Logging Bucket for Load Balancers")
                        """Function to create the bucket for storing load balancer logs"""
                        logging.info("Creating bucket in %s" % org_account)
                        logging.info("CreateBucket API Call")
                        if aws_region == "us-east-1":
                            logging_bucket_dict = s3_ma.create_bucket(
                                Bucket="aws-lb-log-collection-"
                                + org_account
                                + "-"
                                + aws_region
                                + "-"
                                + unique_end
                            )
                        else:
                            logging_bucket_dict = s3_ma.create_bucket(
                                Bucket="aws-lb-log-collection-"
                                + org_account
                                + "-"
                                + aws_region
                                + "-"
                                + unique_end,
                                CreateBucketConfiguration={
                                    "LocationConstraint": aws_region
                                },
                            )
                        logging.info(
                            "Bucket "
                            + "aws-lb-log-collection-"
                            + org_account
                            + "-"
                            + aws_region
                            + "-"
                            + unique_end
                            + " Created."
                        )
                        logging.info("Setting lifecycle policy.")
                        logging.info("PutBucketLifecycleConfiguration API Call")
                        lifecycle_policy = s3_ma.put_bucket_lifecycle_configuration(
                            Bucket="aws-lb-log-collection-"
                            + org_account
                            + "-"
                            + aws_region
                            + "-"
                            + unique_end,
                            LifecycleConfiguration={
                                "Rules": [
                                    {
                                        "Expiration": {"Days": 365},
                                        "Status": "Enabled",
                                        "Prefix": "",
                                        "ID": "LogStorage",
                                        "Transitions": [
                                            {
                                                "Days": 90,
                                                "StorageClass": "INTELLIGENT_TIERING",
                                            }
                                        ],
                                    }
                                ]
                            },
                        )
                        logging.info("Lifecycle Policy successfully set.")
                        logging.info("Checking for AWS Log Account for ELB.")
                        logging.info(
                            "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html"
                        )
                        if aws_region == "us-east-1":
                            elb_account = "127311923021"
                        elif aws_region == "us-east-2":
                            elb_account = "033677994240"
                        elif aws_region == "us-west-1":
                            elb_account = "027434742980"
                        elif aws_region == "us-west-2":
                            elb_account = "797873946194"
                        elif aws_region == "af-south-1":
                            elb_account = "098369216593"
                        elif aws_region == "ca-central-1":
                            elb_account = "985666609251"
                        elif aws_region == "eu-central-1":
                            elb_account = "054676820928"
                        elif aws_region == "eu-west-1":
                            elb_account = "156460612806"
                        elif aws_region == "eu-west-2":
                            elb_account = "652711504416"
                        elif aws_region == "eu-south-1":
                            elb_account = "635631232127"
                        elif aws_region == "eu-west-3":
                            elb_account = "009996457667"
                        elif aws_region == "eu-north-1":
                            elb_account = "897822967062"
                        elif aws_region == "ap-east-1":
                            elb_account = "754344448648"
                        elif aws_region == "ap-northeast-1":
                            elb_account = "582318560864"
                        elif aws_region == "ap-northeast-2":
                            elb_account = "600734575887"
                        elif aws_region == "ap-northeast-3":
                            elb_account = "383597477331"
                        elif aws_region == "ap-southeast-1":
                            elb_account = "114774131450"
                        elif aws_region == "ap-southeast-2":
                            elb_account = "783225319266"
                        elif aws_region == "ap-south-1":
                            elb_account = "718504428378"
                        elif aws_region == "me-south-1":
                            elb_account = "076674570225"
                        elif aws_region == "sa-east-1":
                            elb_account = "507241528517"
                        elif aws_region == "us-gov-west-1":
                            elb_account = "048591011584"
                        elif aws_region == "us-gov-east-1":
                            elb_account = "190560391635"
                        logging.info("Checking for AWS Log Account for ELB.")
                        bucket_policy = {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {
                                        "Service": "delivery.logs.amazonaws.com"
                                    },
                                    "Action": "s3:GetBucketAcl",
                                    "Resource": f"arn:{partition}:s3:::aws-lb-log-collection-{org_account}-{aws_region}-{unique_end}",
                                },
                                {
                                    "Effect": "Allow",
                                    "Principal": {
                                        "Service": "delivery.logs.amazonaws.com"
                                    },
                                    "Action": "s3:PutObject",
                                    "Resource": f"arn:{partition}:s3:::aws-lb-log-collection-{org_account}-{aws_region}-{unique_end}/*",
                                    "Condition": {
                                        "StringEquals": {
                                            "s3:x-amz-acl": "bucket-owner-full-control"
                                        }
                                    },
                                },
                                {
                                    "Effect": "Allow",
                                    "Principal": {
                                        "AWS": f"arn:{partition}:iam::{elb_account}:root"
                                    },
                                    "Action": "s3:PutObject",
                                    "Resource": f"arn:{partition}:s3:::aws-lb-log-collection-{org_account}-{aws_region}-{unique_end}/*",
                                },
                            ],
                        }
                        logging.info("PutBucketPolicy API Call")
                        s3_ma.put_bucket_policy(
                            Bucket=f"aws-lb-log-collection-{org_account}-{aws_region}-{unique_end}",
                            Policy=json.dumps(bucket_policy),
                        )
                        logging.info("Setting the S3 bucket Public Access to Blocked")
                        logging.info("PutPublicAccessBlock API Call")
                        bucket_private = s3_ma.put_public_access_block(
                            Bucket=f"aws-lb-log-collection-{org_account}-{aws_region}-{unique_end}",
                            PublicAccessBlockConfiguration={
                                "BlockPublicAcls": True,
                                "IgnorePublicAcls": True,
                                "BlockPublicPolicy": True,
                                "RestrictPublicBuckets": True,
                            },
                        )
                        if ELBv1LogList != []:
                            for elb in ELBv1LogList:
                                logging.info(
                                    "Activating logs for Load Balancer " + elb[0]
                                )
                                logging.info("ModifyLoadBalancerAttributes API Call")
                                create_lb_log = elbv1_ma.modify_load_balancer_attributes(
                                    LoadBalancerName=elb[0],
                                    LoadBalancerAttributes={
                                        "AccessLog": {
                                            "Enabled": True,
                                            "S3BucketName": f"aws-lb-log-collection-{org_account}-{aws_region}-{unique_end}",
                                            "EmitInterval": 5,
                                            "S3BucketPrefix": elb[0],
                                        }
                                    },
                                )
                                logging.info(
                                    "Logging Enabled for Load Balancer " + elb[0]
                                )
                        if ELBv2LogList != []:
                            for elb in ELBv2LogList:
                                logging.info(
                                    "Activating logs for Load Balancer " + elb[0]
                                )
                                logging.info("ModifyLoadBalancerAttributes v2 API Call")
                                create_lb_log = elbv2_ma.modify_load_balancer_attributes(
                                    LoadBalancerArn=elb[1],
                                    Attributes=[
                                        {
                                            "Key": "access_logs.s3.enabled",
                                            "Value": "true",
                                        },
                                        {
                                            "Key": "access_logs.s3.bucket",
                                            "Value": f"aws-lb-log-collection-{org_account}-{aws_region}-{unique_end}",
                                        },
                                        {
                                            "Key": "access_logs.s3.prefix",
                                            "Value": elb[0],
                                        },
                                    ],
                                )
                                logging.info(
                                    "Logging Enabled for Load Balancer " + elb[0]
                                )
                    else:
                        logging.info(
                            "No Load Balancers WITHOUT logging found within account "
                            + org_account
                            + ", region "
                            + aws_region
                        )
                except Exception as exception_handle:
                    logging.error(exception_handle)


# Turn on GuardDuty and export findings to an S3 bucket.
def check_guardduty(
    region_list,
    account_number,
    OrgAccountIdList,
    bucket_name,
    included_accounts,
    excluded_accounts,
    partition,
):

    account_id_list = json.dumps(OrgAccountIdList)
    logging.info("Creating KMS key for GuardDuty to export findings.")
    kms = boto3.client("kms")
    key_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:{partition}:iam::{account_number}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "Allow GuardDuty to use the key",
                "Effect": "Allow",
                "Principal": {"Service": "guardduty.amazonaws.com"},
                "Action": ["kms:GenerateDataKey"],
                "Resource": "*",
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id_list}},
            },
        ],
    }
    logging.info("CreateKey API Call")
    export_key = kms.create_key(
        Policy=json.dumps(key_policy),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Origin="AWS_KMS",
        MultiRegion=False,
    )
    key_arn = export_key["KeyMetadata"]["Arn"]
    logging.info("Created KMS Key " + key_arn)
    key_alias = "alias/ale-guardduty-key-" + random_string_generator()
    logging.info("CreateAlias API Call")
    kms.create_alias(AliasName=key_alias, TargetKeyId=key_arn)
    logging.info("Created KMS Key Alias " + key_alias)

    logging.info("Creating /guardduty folder in S3 Bucket")
    logging.info("PutObject API Call")
    s3.put_object(Bucket=bucket_name, Key="guardduty/")

    for org_account in OrgAccountIdList:
        if excluded_accounts != "none" and org_account in excluded_accounts:
            continue
        elif included_accounts == "all" or org_account in included_accounts:
            for aws_region in region_list:
                logging.info(
                    "Checking for GuardDuty detectors in the account "
                    + org_account
                    + " in region "
                    + aws_region
                    + "."
                )
                sts = boto3.client("sts")
                RoleArn = f"arn:{partition}:iam::{org_account}:role/Assisted_Log_Enabler_IAM_Role"
                logging.info(
                    f"Assuming Target Role {RoleArn} for Assisted Log Enabler..."
                )
                assisted_log_enabler_sts = sts.assume_role(
                    RoleArn=RoleArn,
                    RoleSessionName="assisted-log-enabler-activation",
                    DurationSeconds=3600,
                )
                guardduty_ma = boto3.client(
                    "guardduty",
                    aws_access_key_id=assisted_log_enabler_sts["Credentials"][
                        "AccessKeyId"
                    ],
                    aws_secret_access_key=assisted_log_enabler_sts["Credentials"][
                        "SecretAccessKey"
                    ],
                    aws_session_token=assisted_log_enabler_sts["Credentials"][
                        "SessionToken"
                    ],
                    region_name=aws_region,
                )
                try:
                    logging.info("ListDetectors API Call")
                    detectors = guardduty_ma.list_detectors()
                    if detectors["DetectorIds"] == []:
                        logging.info(
                            "GuardDuty is not enabled in the account "
                            + org_account
                            + ", region "
                            + aws_region
                        )
                        logging.info("Enabling GuardDuty")
                        logging.info("CreateDetector API Call")
                        new_detector = guardduty_ma.create_detector(
                            Enable=True,
                            DataSources={
                                "S3Logs": {"Enable": True},
                                "Kubernetes": {"AuditLogs": {"Enable": True}},
                            },
                            Tags={"workflow": "assisted-log-enabler"},
                        )
                        logging.info(
                            "Created GuardDuty detector ID "
                            + new_detector["DetectorId"]
                        )

                        logging.info("Exporting GuardDuty findings to an S3 bucket.")
                        logging.info(
                            "Setting S3 Bucket "
                            + bucket_name
                            + " as publishing destination for GuardDuty detector."
                        )
                        logging.info("CreatePublishingDestination API Call")
                        guardduty_ma.create_publishing_destination(
                            DetectorId=new_detector["DetectorId"],
                            DestinationType="S3",
                            DestinationProperties={
                                "DestinationArn": f"arn:{partition}:s3:::{bucket_name}/guardduty",
                                "KmsKeyArn": key_arn,
                            },
                        )
                    else:
                        detector_id = detectors["DetectorIds"][0]
                        logging.info("GetDetector API Call")
                        if (
                            guardduty_ma.get_detector(DetectorId=detector_id)["Status"]
                            == "DISABLED"
                        ):
                            logging.info(
                                "GuardDuty is suspended in the account "
                                + org_account
                                + ", region "
                                + aws_region
                            )
                            logging.info("Enabling GuardDuty")
                            logging.info("UpdateDetector API Call")
                            guardduty_ma.update_detector(
                                DetectorId=detector_id,
                                Enable=True,
                                DataSources={
                                    "S3Logs": {"Enable": True},
                                    "Kubernetes": {"AuditLogs": {"Enable": True}},
                                },
                            )
                        else:
                            logging.info(
                                "GuardDuty is already enabled in the account "
                                + org_account
                                + ", region "
                                + aws_region
                            )

                        logging.info(
                            "Checking if GuardDuty detector publishes findings to S3."
                        )
                        logging.info("ListPublishingDestinations API Call")
                        gd_destinations = guardduty_ma.list_publishing_destinations(
                            DetectorId=detector_id
                        )["Destinations"]
                        if gd_destinations == []:
                            logging.info(
                                "Detector does not publish findings to a destination. Setting S3 Bucket "
                                + bucket_name
                                + " as publishing destination for GuardDuty detector."
                            )
                            logging.info("CreatePublishingDestination API Call")
                            guardduty_ma.create_publishing_destination(
                                DetectorId=detector_id,
                                DestinationType="S3",
                                DestinationProperties={
                                    "DestinationArn": f"arn:{partition}:s3:::{bucket_name}/guardduty",
                                    "KmsKeyArn": key_arn,
                                },
                            )
                        else:
                            for dest in gd_destinations:
                                if dest["DestinationType"] == "S3":
                                    dest_id = dest["DestinationId"]
                                    logging.info(
                                        "DescribePublishingDestination API Call"
                                    )
                                    dest_info = (
                                        guardduty_ma.describe_publishing_destination(
                                            DetectorId=detector_id,
                                            DestinationId=dest_id,
                                        )
                                    )
                                    dest_s3_arn = dest_info["DestinationProperties"][
                                        "DestinationArn"
                                    ]
                                    logging.info(
                                        "Detector already publishes findings to S3 bucket "
                                        + dest_s3_arn.split(":")[-1]
                                    )

                except Exception as exception_handle:
                    logging.error(exception_handle)


# Turn on WAFv2 logging
def wafv2_logs(
    region_list,
    OrgAccountIdList,
    organization_id,
    included_accounts,
    excluded_accounts,
    partition,
):
    bucket_arn = ""
    account_number = get_account_number()

    # Check Web ACLs in every account for logging and enable it if not already enabled
    for org_account in OrgAccountIdList:
        if excluded_accounts != "none" and org_account in excluded_accounts:
            continue
        elif included_accounts == "all" or org_account in included_accounts:
            for aws_region in region_list:
                logging.info(
                    "Checking for WAF Logging in the account "
                    + org_account
                    + ", region "
                    + aws_region
                    + "."
                )
                sts = boto3.client("sts")
                RoleArn = f"arn:{partition}:iam::{org_account}:role/Assisted_Log_Enabler_IAM_Role"
                logging.info(
                    f"Assuming Target Role {RoleArn} for Assisted Log Enabler..."
                )
                assisted_log_enabler_sts = sts.assume_role(
                    RoleArn=RoleArn,
                    RoleSessionName="assisted-log-enabler-activation",
                    DurationSeconds=3600,
                )
                wafv2_ma = boto3.client(
                    "wafv2",
                    aws_access_key_id=assisted_log_enabler_sts["Credentials"][
                        "AccessKeyId"
                    ],
                    aws_secret_access_key=assisted_log_enabler_sts["Credentials"][
                        "SecretAccessKey"
                    ],
                    aws_session_token=assisted_log_enabler_sts["Credentials"][
                        "SessionToken"
                    ],
                    region_name=aws_region,
                )

                try:
                    WAFv2List: list = []  # list of all WAFv2 ARNs
                    WAFv2LogList: list = []  # list of WAFv2 ARNs with logging enabled
                    WAFv2NoLogList: list = []  # list of WAFv2 ARNs to enable logging

                    # Get regional WAFv2 Web ACLs
                    logging.info("ListWebAcls API Call")
                    wafv2_regional_acl_list = wafv2_ma.list_web_acls(Scope="REGIONAL")[
                        "WebACLs"
                    ]
                    for acl in wafv2_regional_acl_list:
                        WAFv2List.append(acl["ARN"])

                    if aws_region == "us-east-1":
                        # Get CloudFront (global) WAFv2 Web ACLs
                        logging.info("Checking for Global (CloudFront) Web ACLs")
                        logging.info("ListWebAcls API Call")
                        wafv2_cf_acl_list = wafv2_ma.list_web_acls(Scope="CLOUDFRONT")[
                            "WebACLs"
                        ]
                        for acl in wafv2_cf_acl_list:
                            WAFv2List.append(acl["ARN"])

                    logging.info(
                        "List of Web ACLs found within account "
                        + org_account
                        + ", region "
                        + aws_region
                        + ":"
                    )
                    print(WAFv2List)

                    # ListLoggingConfigurations returns only Web ACLs with logging already enabled
                    logging.info("ListLoggingConfigurations API Call")
                    wafv2_regional_log_configs = wafv2_ma.list_logging_configurations(
                        Scope="REGIONAL"
                    )["LoggingConfigurations"]
                    for acl in wafv2_regional_log_configs:
                        WAFv2LogList.append(acl["ResourceArn"])

                    if aws_region == "us-east-1":
                        logging.info(
                            "Checking Global (CloudFront) Web ACL Logging Configurations"
                        )
                        logging.info("ListLoggingConfigurations API Call")
                        wafv2_cf_log_configs = wafv2_ma.list_logging_configurations(
                            Scope="CLOUDFRONT"
                        )["LoggingConfigurations"]
                        for acl in wafv2_cf_log_configs:
                            WAFv2LogList.append(acl["ResourceArn"])

                    WAFv2NoLogList = list(set(WAFv2List) - set(WAFv2LogList))
                    logging.info(
                        "List of Web ACLs found within account "
                        + org_account
                        + ", region "
                        + aws_region
                        + " WITHOUT logging enabled:"
                    )
                    print(WAFv2NoLogList)

                    # If an S3 bucket hasn't been created yet, create one
                    if WAFv2NoLogList != [] and bucket_arn == "":
                        logging.info(
                            "Creating S3 bucket for WAF logs enabled by Assisted Log Enabler."
                        )
                        unique_end = random_string_generator()
                        bucket_name = (
                            "aws-waf-logs-ale-" + account_number + "-" + unique_end
                        )
                        logging.info("CreateBucket API Call")
                        s3.create_bucket(Bucket=bucket_name)
                        logging.info("Bucket " + bucket_name + " created.")
                        bucket_arn = f"arn:{partition}:s3:::{bucket_name}"

                        # Set lifecycle policy and block public access
                        logging.info("Setting lifecycle policy.")
                        logging.info("PutBucketLifecycleConfiguration API Call")
                        s3.put_bucket_lifecycle_configuration(
                            Bucket=bucket_name,
                            LifecycleConfiguration={
                                "Rules": [
                                    {
                                        "Expiration": {"Days": 365},
                                        "Status": "Enabled",
                                        "Prefix": "",
                                        "ID": "LogStorage",
                                        "Transitions": [
                                            {
                                                "Days": 90,
                                                "StorageClass": "INTELLIGENT_TIERING",
                                            }
                                        ],
                                    }
                                ]
                            },
                        )
                        logging.info("Setting the S3 bucket Public Access to Blocked")
                        logging.info("PutPublicAccessBlock API Call")
                        bucket_private = s3.put_public_access_block(
                            Bucket=bucket_name,
                            PublicAccessBlockConfiguration={
                                "BlockPublicAcls": True,
                                "IgnorePublicAcls": True,
                                "BlockPublicPolicy": True,
                                "RestrictPublicBuckets": True,
                            },
                        )

                        logging.info(
                            "Setting the S3 bucket policy to allow multi-account access."
                        )
                        bucket_policy = {
                            "Version": "2012-10-17",
                            "Id": "AWSLogDeliveryWrite20150319",
                            "Statement": [
                                {
                                    "Sid": "AWSLogDeliveryWrite",
                                    "Effect": "Allow",
                                    "Principal": {
                                        "Service": "delivery.logs.amazonaws.com"
                                    },
                                    "Action": "s3:PutObject",
                                    "Resource": f"{bucket_arn}/*",
                                    "Condition": {
                                        "StringEquals": {
                                            "aws:ResourceOrgID": organization_id
                                        }
                                    },
                                },
                                {
                                    "Sid": "AWSLogDeliveryAclCheck",
                                    "Effect": "Allow",
                                    "Principal": {
                                        "Service": "delivery.logs.amazonaws.com"
                                    },
                                    "Action": "s3:GetBucketAcl",
                                    "Resource": bucket_arn,
                                    "Condition": {
                                        "StringEquals": {
                                            "aws:ResourceOrgID": organization_id
                                        }
                                    },
                                },
                            ],
                        }
                        logging.info("PutBucketPolicy API Call")
                        s3.put_bucket_policy(
                            Bucket=bucket_name,
                            Policy=json.dumps(bucket_policy),
                        )

                    # If an S3 bucket has been created, use it as the log destination
                    if WAFv2NoLogList != [] and bucket_arn != "":
                        for arn in WAFv2NoLogList:
                            logging.info(
                                arn
                                + " does not have logging turned on. Turning on logging."
                            )
                            logging.info("PutLoggingConfiguration API Call")
                            wafv2_ma.put_logging_configuration(
                                LoggingConfiguration={
                                    "ResourceArn": arn,
                                    "LogDestinationConfigs": [
                                        bucket_arn,
                                    ],
                                }
                            )
                    else:
                        logging.info(
                            "No WAFv2 Web ACLs to enable logging for in account "
                            + org_account
                            + ", region "
                            + aws_region
                            + "."
                        )

                except Exception as exception_handle:
                    logging.error(exception_handle)


# Runs the defined EKS logging code
def run_eks(included_accounts="all", excluded_accounts="none"):
    partition = get_partition()
    region_list = get_region_list(partition)
    OrgAccountIdList = org_account_grab()[0]
    eks_logging(
        region_list, OrgAccountIdList, included_accounts, excluded_accounts, partition
    )
    logging.info(
        "This is the end of the script. Please feel free to validate that logs have been turned on."
    )


# Runs the defined VPC flow logging code
def run_vpc_flow_logs(
    bucket_name="default", included_accounts="all", excluded_accounts="none"
):
    partition = get_partition()
    region_list = get_region_list(partition)
    OrgAccountIdList = org_account_grab()[0]
    account_number = get_account_number()
    if bucket_name == "default":
        unique_end = random_string_generator()
        bucket_name = create_bucket(
            OrgAccountIdList, account_number, unique_end, partition
        )
    else:
        update_custom_bucket_policy(
            bucket_name, account_number, OrgAccountIdList, partition
        )

    flow_log_activator(
        OrgAccountIdList,
        region_list,
        bucket_name,
        included_accounts,
        excluded_accounts,
        partition,
    )
    logging.info(
        "This is the end of the script. Please feel free to validate that logs have been turned on."
    )


# Runs the defined Route53 query logging code
def run_r53_query_logs(
    bucket_name="default", included_accounts="all", excluded_accounts="none"
):
    partition = get_partition()
    region_list = get_region_list(partition)
    OrgAccountIdList = org_account_grab()[0]
    account_number = get_account_number()
    if bucket_name == "default":
        unique_end = random_string_generator()
        bucket_name = create_bucket(
            OrgAccountIdList, account_number, unique_end, partition
        )
    else:
        update_custom_bucket_policy(
            bucket_name, account_number, OrgAccountIdList, partition
        )

    route_53_query_logs(
        region_list,
        OrgAccountIdList,
        bucket_name,
        included_accounts,
        excluded_accounts,
        partition,
    )
    logging.info(
        "This is the end of the script. Please feel free to validate that logs have been turned on."
    )


# Runs the defined S3 access logging code
def run_s3_logs(included_accounts="all", excluded_accounts="none"):
    partition = get_partition()
    region_list = get_region_list(partition)
    unique_end = random_string_generator()
    OrgAccountIdList = org_account_grab()[0]
    s3_logs(
        region_list,
        OrgAccountIdList,
        unique_end,
        included_accounts,
        excluded_accounts,
        partition,
    )
    logging.info(
        "This is the end of the script. Please feel free to validate that logs have been turned on."
    )


# Runs the defined Load Balancer logging code
def run_lb_logs(included_accounts="all", excluded_accounts="none"):
    partition = get_partition()
    region_list = get_region_list(partition)
    unique_end = random_string_generator()
    OrgAccountIdList = org_account_grab()[0]
    lb_logs(
        region_list,
        OrgAccountIdList,
        unique_end,
        included_accounts,
        excluded_accounts,
        partition,
    )
    logging.info(
        "This is the end of the script. Please feel free to validate that logs have been turned on."
    )


# Runs the defined GuardDuty enablement code and exports findings to an S3 bucket
def run_guardduty(
    bucket_name="default", included_accounts="all", excluded_accounts="none"
):
    partition = get_partition()
    region_list = get_region_list(partition)
    OrgAccountIdList = org_account_grab()[0]
    account_number = get_account_number()
    if bucket_name == "default":
        unique_end = random_string_generator()
        bucket_name = create_bucket(
            OrgAccountIdList, account_number, unique_end, partition
        )
    else:
        update_custom_bucket_policy(
            bucket_name, account_number, OrgAccountIdList, partition
        )

    check_guardduty(
        region_list,
        account_number,
        OrgAccountIdList,
        bucket_name,
        included_accounts,
        excluded_accounts,
        partition,
    )
    logging.info(
        "This is the end of the script. Please feel free to validate that logs have been turned on."
    )


# Runs the defined WAFv2 logging code
def run_wafv2_logs(included_accounts="all", excluded_accounts="none"):
    partition = get_partition()
    region_list = get_region_list(partition)
    OrgAccountIdList, organization_id = org_account_grab()
    wafv2_logs(
        region_list,
        OrgAccountIdList,
        organization_id,
        included_accounts,
        excluded_accounts,
        partition,
    )
    logging.info(
        "This is the end of the script. Please feel free to validate that logs have been turned on."
    )


# Runs all of the log enablement functions
def lambda_handler(
    event,
    context,
    bucket_name="default",
    included_accounts="all",
    excluded_accounts="none",
):
    partition = get_partition()
    region_list = get_region_list(partition)
    unique_end = random_string_generator()
    account_number = get_account_number()
    OrgAccountIdList, organization_id = org_account_grab()
    if bucket_name == "default":
        bucket_name = create_bucket(
            OrgAccountIdList, account_number, unique_end, partition
        )
    else:
        update_custom_bucket_policy(
            bucket_name, account_number, OrgAccountIdList, partition
        )
    flow_log_activator(
        OrgAccountIdList,
        region_list,
        bucket_name,
        included_accounts,
        excluded_accounts,
        partition,
    )
    eks_logging(
        region_list, OrgAccountIdList, included_accounts, excluded_accounts, partition
    )
    route_53_query_logs(
        region_list,
        OrgAccountIdList,
        bucket_name,
        included_accounts,
        excluded_accounts,
        partition,
    )
    s3_logs(
        region_list,
        OrgAccountIdList,
        unique_end,
        included_accounts,
        excluded_accounts,
        partition,
    )
    lb_logs(
        region_list,
        OrgAccountIdList,
        unique_end,
        included_accounts,
        excluded_accounts,
        partition,
    )
    wafv2_logs(
        region_list,
        OrgAccountIdList,
        organization_id,
        included_accounts,
        excluded_accounts,
        partition,
    )
    logging.info(
        "This is the end of the script. Please feel free to validate that logs have been turned on."
    )


if __name__ == "__main__":
    event = "event"
    context = "context"
    lambda_handler(event, context)
