#!/usr/bin/env jq -rf

# Data source: https://ip-ranges.amazonaws.com/ip-ranges.json
#
# Doc: https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html

.prefixes[] | select(.region == "eu-central-1" and .service == "EC2") | .ip_prefix
