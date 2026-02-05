import os, json, base64, requests

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_OWNER = os.getenv("GITHUB_REPO_OWNER", "wealthoceaninstitute-commits")
GITHUB_REPO  = os.getenv("GITHUB_REPO_NAME", "Multiuser_clients")
BRANCH = os.getenv("GITHUB_BRANCH", "main")





def github_write_json(path: str, data: dict) -> None:
    """
    Write a JSON document to a GitHub repository.

    :param path: The repository path (e.g. "data/users/uid/profile.json").
    :param data: The JSON data to write.
    :raises Exception: if the write fails.

    This function constructs the correct API endpoint based on the
    configured owner and repository.  It encodes the payload as Base64,
    sets a commit message, and writes to the specified branch.  If
    configuration is incomplete (e.g. missing token), an exception
    describing the missing variable is raised.  If the request fails,
    an exception with the HTTP status and response text is raised.
    """
    # ensure configuration is present
    if not GITHUB_TOKEN:
        raise Exception("GITHUB_TOKEN environment variable is missing")
    if not GITHUB_OWNER or not GITHUB_REPO:
        raise Exception("GITHUB_REPO_OWNER and GITHUB_REPO_NAME must be set")

    url = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/contents/{path}"
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
    }
    content = base64.b64encode(
        json.dumps(data, indent=2).encode()
    ).decode()
    payload = {
        "message": f"create {path}",
        "content": content,
        "branch": BRANCH,
    }
    r = requests.put(url, headers=headers, json=payload, timeout=15)
    if r.status_code not in (200, 201):
        raise Exception(f"GitHub write failed: {r.status_code} {r.text}")
