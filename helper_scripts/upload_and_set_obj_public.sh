#!/bin/bash
set -e

bkt_name="UPDATE-YOUR-BUCKET-NAME-HERE"
obj_key="confidential.html"

# Uploade the object
aws s3 cp ./helper_scripts/${obj_key} s3://${bkt_name}/

# Request for the ACL
echo -n "========= Private ACL ========="
aws s3api get-object-acl  --bucket ${bkt_name} --key ${obj_key}

# Modify the ACL
aws s3api put-object-acl \
    --bucket ${bkt_name} \
    --key ${obj_key} \
    --acl public-read

# Request for ACL AGAIN
echo -n "========= Public ACL ========="
aws s3api get-object-acl  --bucket ${bkt_name} --key ${obj_key}