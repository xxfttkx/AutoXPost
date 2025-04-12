import os
import sys
import base64
import hashlib
import re
import time
from dotenv import load_dotenv
import requests
from requests_oauthlib import OAuth2Session
from requests.auth import HTTPBasicAuth
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend
from nacl import encoding, public

MEDIA_ENDPOINT_URL = 'https://api.x.com/2/media/upload'
POST_TO_X_URL = 'https://api.x.com/2/tweets'

# Replace with path to file
VIDEO_FILENAME = 'output.png'

# You will need to enable OAuth 2.0 in your App’s auth settings in the Developer Portal to get your client ID.
# Inside your terminal you will need to set an enviornment variable
# export CLIENT_ID='your-client-id'
load_dotenv()
# client_id = os.environ.get("CLIENT_ID")
client_id = os.getenv("CLIENT_ID")
client_secret = os.getenv("CLIENT_SECRET")

# If you have selected a type of App that is a confidential client you will need to set a client secret.
# Confidential Clients securely authenticate with the authorization server.

# Inside your terminal you will need to set an enviornment variable
# export CLIENT_SECRET='your-client-secret'

# Remove the comment on the following line if you are using a confidential client
# client_secret = os.environ.get("CLIENT_SECRET")

# Replace the following URL with your callback URL, which can be obtained from your App's auth settings.
redirect_uri = "https://www.example.com"
redirect_uri = "https://example.com/callback"

# Define token URL
token_url = "https://api.x.com/2/oauth2/token"

def need_post():
    # GitHub 上图片的原始链接（Raw）
    img_url = "https://raw.githubusercontent.com/xxfttkx/splatoon_SalmonRun_weapons/main/output.png"

    # 本地路径
    local_img = "output.png"
    temp_img = "temp.png"
    # 下载图片为 temp.png
    r = requests.get(img_url)
    with open(temp_img, 'wb') as f:
        f.write(r.content)
    # 计算 MD5 用于比较是否相同
    def file_md5(path):
        with open(path, 'rb') as f:
            return hashlib.md5(f.read()).hexdigest()
    need_update = False
    if not os.path.exists(local_img):
        need_update = True
    else:
        if file_md5(local_img) != file_md5(temp_img):
            need_update = True
    # 如果需要更新
    if need_update:
        # 覆盖 output.png
        os.replace(temp_img, local_img)
    return need_update

def encrypt_secret(public_key: str, secret_value: str) -> str:
    """使用 GitHub 返回的 Base64 编码公钥加密 Secret"""
    public_key_bytes = base64.b64decode(public_key)
    sealed_box = public.SealedBox(public.PublicKey(public_key_bytes))
    encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
    return base64.b64encode(encrypted).decode("utf-8")

def save_refresh_token(new_refresh_token):
    """
    Save the latest refresh token, replacing the old one if it exists.
    """
    """
    Save the latest refresh token to .env and update GitHub Secrets.
    """
    # ---- 1. 保存到本地 .env 文件（如果存在） ----
    if os.path.exists('.env'):
        lines = []
        token_found = False
        with open('.env', 'r') as f:
            lines = f.readlines()

        with open('.env', 'w') as f:
            for line in lines:
                if line.startswith('REFRESH_TOKEN='):
                    line = f"REFRESH_TOKEN={new_refresh_token}\n"
                    token_found = True
                f.write(line)

            if not token_found:
                f.write(f"REFRESH_TOKEN={new_refresh_token}\n")
    else:
        # ---- 2. 上传到 GitHub Secrets ----
        GITHUB_TOKEN = os.getenv("MY_PAT")
        
        REPO_OWNER = 'xxfttkx'
        REPO_NAME = 'AutoXPost'
        SECRET_NAME = "REFRESH_TOKEN"

        if not all([GITHUB_TOKEN, REPO_OWNER, REPO_NAME]):
            raise Exception("Missing GITHUB_TOKEN, REPO_OWNER, or REPO_NAME in environment variables.")

        # Step 1: 获取公钥
        url = f'https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/actions/secrets/public-key'
        headers = {
            'Authorization': f'token {GITHUB_TOKEN}',
            'Accept': 'application/vnd.github.v3+json'
        }

        response = requests.get(url, headers=headers)
        response.raise_for_status()

        public_key = response.json()["key"]
        key_id = response.json()["key_id"]

        # Step 2: 加密 token
        encrypted_value = encrypt_secret(public_key, new_refresh_token)

        # Step 3: 提交更新
        update_url = f'https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/actions/secrets/{SECRET_NAME}'
        payload = {
            "encrypted_value": encrypted_value,
            "key_id": key_id
        }

        put_response = requests.put(update_url, headers=headers, json=payload)
        put_response.raise_for_status()
        print("✅ REFRESH_TOKEN 已成功更新至 GitHub Secrets。")

def refresh_token_flow():
    """
    Use refresh_token to get a new access_token
    """
    refresh_token = os.getenv("REFRESH_TOKEN")
    if not refresh_token:
        print("No refresh token found. Please authorize manually first.")
        sys.exit(1)

    # Prepare data for refreshing token
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
    }

    # HTTP Basic Auth for confidential client
    auth = HTTPBasicAuth(client_id, client_secret)

    # Request new access token
    resp = requests.post(token_url, data=data, auth=auth)
    if resp.status_code != 200:
        print(f"Error refreshing token: {resp.text}")
        sys.exit(1)

    token = resp.json()
    access_token = token["access_token"]
    new_refresh_token = token.get("refresh_token", refresh_token)

    # Save the new refresh_token to .env file
    save_refresh_token(new_refresh_token)

    return access_token

def manual_authorization_flow():
    # Set the scopes
    scopes = ["media.write", "users.read", "tweet.read", "tweet.write", "offline.access"]

    # Create a code verifier
    code_verifier = base64.urlsafe_b64encode(os.urandom(30)).decode("utf-8")
    code_verifier = re.sub("[^a-zA-Z0-9]+", "", code_verifier)

    # Create a code challenge
    code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).decode("utf-8")
    code_challenge = code_challenge.replace("=", "")

    # Start and OAuth 2.0 session
    oauth = OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scopes)

    # Create an authorize URL
    auth_url = "https://x.com/i/oauth2/authorize"
    authorization_url, state = oauth.authorization_url(
        auth_url, code_challenge=code_challenge, code_challenge_method="S256"
    )

    # Visit the URL to authorize your App to make requests on behalf of a user
    print(
        "Visit the following URL to authorize your App on behalf of your X handle in a browser:"
    )
    print(authorization_url)

    # Paste in your authorize URL to complete the request
    authorization_response = input(
        "Paste in the full URL after you've authorized your App:\n"
    )

    # Fetch your access token
    token_url = "https://api.x.com/2/oauth2/token"

    # The following line of code will only work if you are using a type of App that is a public client
    auth = False

    # If you are using a confidential client you will need to pass in basic encoding of your client ID and client secret.

    # Please remove the comment on the following line if you are using a type of App that is a confidential client
    # auth = HTTPBasicAuth(client_id, client_secret)

    token = oauth.fetch_token(
        token_url=token_url,
        authorization_response=authorization_response,
        auth=HTTPBasicAuth(client_id, client_secret),
        client_id=client_id,
        include_client_id=True,
        code_verifier=code_verifier,
    )

    # Save the refresh token to .env
    with open('.env', 'a') as f:
        f.write(f"REFRESH_TOKEN={token['refresh_token']}\n")

    return token["access_token"]

def get_access_token():
    """
    Get access token: either refresh it or request it manually
    """
    if os.getenv("REFRESH_TOKEN"):
        return refresh_token_flow()
    else:
        return manual_authorization_flow()



class VideoPost(object):

    def __init__(self, file_name):
        # Defines video Post properties
        self.video_filename = file_name
        self.total_bytes = os.path.getsize(self.video_filename)
        self.media_id = None
        self.processing_info = None

    def upload_init(self):
        # Initializes Upload
        print('INIT')

        request_data = {
            'command': 'INIT',
            'media_type': 'image/png',
            'total_bytes': self.total_bytes,
            'media_category': 'tweet_image'
        }

        req = requests.post(url=MEDIA_ENDPOINT_URL, params=request_data, headers=headers)
        print(req.status_code)
        print(req.text)
        media_id = req.json()['data']['id']

        self.media_id = media_id

        print('Media ID: %s' % str(media_id))

    def upload_append(self):
        segment_id = 0
        bytes_sent = 0
        with open(self.video_filename, 'rb') as file:
            while bytes_sent < self.total_bytes:
                chunk = file.read(4 * 1024 * 1024)  # 4MB chunk size

                print('APPEND')

                files = {'media': ('chunk', chunk, 'application/octet-stream')}

                data = {
                    'command': 'APPEND',
                    'media_id': self.media_id,
                    'segment_index': segment_id
                }

                req = requests.post(url=MEDIA_ENDPOINT_URL, data=data, files=files, headers=headers)

                if req.status_code < 200 or req.status_code > 299:
                    print(req.status_code)
                    print(req.text)
                    sys.exit(0)

                segment_id += 1
                bytes_sent = file.tell()

                print(f'{bytes_sent} of {self.total_bytes} bytes uploaded')

        print('Upload chunks complete.')

    def upload_finalize(self):

        # Finalizes uploads and starts video processing
        print('FINALIZE')

        request_data = {
            'command': 'FINALIZE',
            'media_id': self.media_id
        }

        req = requests.post(url=MEDIA_ENDPOINT_URL, params=request_data, headers=headers)

        print(req.json())

        self.processing_info = req.json()['data'].get('processing_info', None)
        self.check_status()

    def check_status(self):
        # Checks video processing status
        if self.processing_info is None:
            return

        state = self.processing_info['state']

        print('Media processing status is %s ' % state)

        if state == u'succeeded':
            return

        if state == u'failed':
            sys.exit(0)

        check_after_secs = self.processing_info['check_after_secs']

        print('Checking after %s seconds' % str(check_after_secs))
        time.sleep(check_after_secs)

        print('STATUS')

        request_params = {
            'command': 'STATUS',
            'media_id': self.media_id
        }

        req = requests.get(url=MEDIA_ENDPOINT_URL, params=request_params, headers=headers)

        self.processing_info = req.json()['data'].get('processing_info', None)
        self.check_status()

    def post(self):

        # Publishes Post with attached video
        payload = {
            'text': '',
            'media': {
                'media_ids': [self.media_id]
            }
        }

        req = requests.post(url=POST_TO_X_URL, json=payload, headers=headers)

        print(req.json())


if __name__ == '__main__':
    if need_post():
        access_token = get_access_token()
        # Set headers with the access token
        headers = {
            "Authorization": f"Bearer {access_token}",
            "User-Agent": "MediaUploadSampleCode",
        }
        videoPost = VideoPost(VIDEO_FILENAME)
        videoPost.upload_init()
        videoPost.upload_append()
        videoPost.upload_finalize()
        videoPost.post()