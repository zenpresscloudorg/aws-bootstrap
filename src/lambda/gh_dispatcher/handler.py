import json
import os
import urllib.request
import boto3

def get_github_token():
    secret_id = os.environ["SECRET_GHTOKEN_DISPATCHER"]
    client = boto3.client("secretsmanager")
    response = client.get_secret_value(SecretId=secret_id)
    return response["SecretString"]

def lambda_handler(event, context):
    github_token = get_github_token()
    org = os.environ["GITHUB_ORG"]
    repo = os.environ["GITHUB_REPO"]

    url = f"https://api.github.com/repos/{org}/{repo}/dispatches"
    data = json.dumps({"event_type": "manual-trigger"}).encode("utf-8")

    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("Authorization", f"token {github_token}")
    req.add_header("User-Agent", "lambda-github-dispatch")

    try:
        with urllib.request.urlopen(req) as response:
            status = response.getcode()
            return {"statusCode": status, "body": "Dispatch enviado"}
    except Exception as e:
        return {"statusCode": 500, "body": str(e)}
