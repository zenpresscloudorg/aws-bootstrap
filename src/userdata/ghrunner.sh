#!/bin/bash
sudo yum update -y
sudo yum install -y dnf-plugins-core wget git unzip tar gzip jq glibc libgcc libstdc++ openssl-libs krb5-libs zlib libicu

# Github
sudo yum config-manager --add-repo https://cli.github.com/packages/rpm/gh-cli.repo
sudo yum update -y
sudo yum install -y gh

# Python
sudo yum install -y python3

# Nodejs
sudo yum install -y nodejs npm

# Yq
sudo wget https://github.com/mikefarah/yq/releases/latest/download/yq_linux_arm64 -q -O /usr/local/bin/yq
sudo chmod +x /usr/local/bin/yq

# Terraform
TERRAFORM_VERSION=$(curl -s https://api.releases.hashicorp.com/v1/releases/terraform/latest | jq -r .version)
wget -q -O terraform_${TERRAFORM_VERSION}_linux_arm64.zip "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_arm64.zip"
unzip -q terraform_${TERRAFORM_VERSION}_linux_arm64.zip
sudo mv terraform /usr/local/bin/
sudo rm -f terraform_${TERRAFORM_VERSION}_linux_arm64.zip

# Terragrunt
TG_VERSION=$(curl -s https://api.github.com/repos/gruntwork-io/terragrunt/releases/latest | jq -r .tag_name)
wget -q "https://github.com/gruntwork-io/terragrunt/releases/download/${TG_VERSION}/terragrunt_linux_arm64" -O terragrunt_linux_arm64
sudo mv terragrunt_linux_arm64 /usr/local/bin/terragrunt
sudo chmod +x /usr/local/bin/terragrunt

# Ansible
sudo yum install -y ansible

# AWS CLI
curl -s -o awscliv2.zip "https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip"
unzip -q awscliv2.zip
sudo ./aws/install
sudo rm -rf aws awscliv2.zip

# GitHub Actions Runner
RUNNER_USER="runner"
ARCH="arm64"
RUNNER_VERSION="$(curl -s https://api.github.com/repos/actions/runner/releases/latest | jq -r .tag_name | tr -d 'v')"
RUNNER_HOME="/opt/actions-runner"
sudo useradd --system --create-home --shell /bin/bash "$RUNNER_USER"
sudo mkdir -p "$RUNNER_HOME"
sudo chown "$RUNNER_USER:$RUNNER_USER" "$RUNNER_HOME"
sudo curl -Ls -o "$RUNNER_HOME/actions-runner-linux-$ARCH-$RUNNER_VERSION.tar.gz" \
"https://github.com/actions/runner/releases/download/v$RUNNER_VERSION/actions-runner-linux-$ARCH-$RUNNER_VERSION.tar.gz"
if ! sudo tar -xzf "$RUNNER_HOME/actions-runner-linux-$ARCH-$RUNNER_VERSION.tar.gz" -C "$RUNNER_HOME"; then
	echo "Error extracting runner" >&2
	exit 1
fi
sudo rm -f "$RUNNER_HOME/actions-runner-linux-$ARCH-$RUNNER_VERSION.tar.gz"
sudo chown -R "$RUNNER_USER:$RUNNER_USER" "$RUNNER_HOME"
sudo -u "$RUNNER_USER" "$RUNNER_HOME/config.sh" \
	--unattended \
	--url "https://github.com/$GH_ORG" \
	--token "$GH_RUNNER_TOKEN" \
	--name "$GH_RUNNER_NAME" \
	--labels "$GH_RUNNER_NAME"
sudo bash -c "cd '$RUNNER_HOME' && ./svc.sh install '$RUNNER_USER'"
sudo bash -c "cd '$RUNNER_HOME' && ./svc.sh start"