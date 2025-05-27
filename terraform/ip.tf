#!/bin/bash

set -e

echo -e "\n--> Bootstrapping Project\n"

echo -e "\n--> Loading environment variables\n"
source secrets

# Check vars
[ -z "$TF_VAR_do_token" ] && echo "TF_VAR_do_token is not set" && exit
[ -z "$SPACE_NAME" ] && echo "SPACE_NAME is not set" && exit
[ -z "$STATE_FILE" ] && echo "STATE_FILE is not set" && exit
[ -z "$AWS_ACCESS_KEY_ID" ] && echo "AWS_ACCESS_KEY_ID is not set" && exit
[ -z "$AWS_SECRET_ACCESS_KEY" ] && echo "AWS_SECRET_ACCESS_KEY is not set" && exit

echo -e "\n--> Initializing terraform\n"
terraform init \
    -backend-config "bucket=$SPACE_NAME" \
    -backend-config "key=$STATE_FILE" \
    -backend-config "access_key=$AWS_ACCESS_KEY_ID" \
    -backend-config "secret_key=$AWS_SECRET_ACCESS_KEY"

echo -e "\n--> Validating terraform configuration\n"
terraform validate

echo -e "\n--> Creating Infrastructure\n"
terraform apply -auto-approve

# Optional: remove this if config is inside the nginx image
# echo -e "\n--> Generating loadbalancer configuration\n"
# bash scripts/gen_load_balancer_config.sh

# echo -e "\n--> Copying loadbalancer configuration to nodes\n"
# bash scripts/scp_load_balancer_config.sh

echo -e "\n--> Deploying stack\n"
ssh \
    -o 'StrictHostKeyChecking no' \
    root@$(terraform output -raw swarm_manager_ip) \
    -i ssh_key/terraform \
    'docker stack deploy myapp -c docker-stack.yml'

echo -e "\n Done bootstrapping"
echo -e "--> Visit: http://$(terraform output -raw loadbalancer_ip)"
echo -e "--> Swarm status: http://$(terraform output -raw swarm_manager_ip):8888"
