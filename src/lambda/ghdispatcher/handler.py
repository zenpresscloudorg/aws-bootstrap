import json
import os
import urllib.request
import boto3

def get_secret():
    secret_id = os.environ["SECRET_GHDISPATCHER"]
    client = boto3.client("secretsmanager")
    response = client.get_secret_value(SecretId=secret_id)
    return response["SecretString"]

def lambda_handler(event, context):

    # Decode secret JSON
    secret_json = json.loads(get_secret())
    gh_dispatcher_token = secret_json.get("gh_dispatcher_token")
    api_auth = secret_json.get("api_auth")

    # Only allow GET method
    if event.get("httpMethod") != "GET":
        return {"statusCode": 405, "body": "Method not allowed"}

    # Get URL parameters
    params = event.get("queryStringParameters") or {}
    repo = params.get("repo")
    static_token = params.get("token")

    # Validate parameters
    if not repo or not static_token:
        return {"statusCode": 400, "body": "Missing 'repo' or 'token' parameter"}

    # Validate static token against api_auth from secret
    if static_token != api_auth:
        return {"statusCode": 401, "body": "Invalid static token"}

    org = os.environ["GH_ORG"]

    url = f"https://api.github.com/repos/{org}/{repo}/dispatches"
    data = json.dumps({"event_type": "manual-trigger"}).encode("utf-8")

    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("Authorization", f"token {gh_dispatcher_token}")
    req.add_header("User-Agent", "lambda-github-dispatch")

    try:
        with urllib.request.urlopen(req) as response:
            status = response.getcode()
            return {"statusCode": status, "body": "Dispatch sent"}
    except Exception as e:
        return {"statusCode": 500, "body": str(e)}
