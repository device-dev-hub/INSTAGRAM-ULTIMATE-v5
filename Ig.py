 #!/usr/bin/env python3
# pyright: reportOptionalMemberAccess=false
# pyright: reportOptionalSubscript=false
# pyright: reportArgumentType=false
"""
THE ULTRA HYPER BOT - Instagram Telegram Bot
Full-featured Instagram automation via Telegram
Multi-user support with secure credential storage
"""

import os
import time
import json
import asyncio
import logging
import re
import shutil
import random
from pathlib import Path
from typing import Dict, List, Optional, Set, Any
from itertools import count
import httpx
import uuid
import hashlib

import aiohttp
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, MessageHandler, filters, 
    ContextTypes, ConversationHandler, CallbackQueryHandler
)
from instagrapi import Client
from instagrapi.exceptions import LoginRequired, ChallengeRequired, TwoFactorRequired
from playwright.async_api import async_playwright

IG_USER_AGENT = "Instagram 148.0.0.33.121 Android (28/9; 480dpi; 1080x2137; HUAWEI; JKM-LX1; HWJKM-H; kirin710; en_US; 216817344)"
IG_APP_ID = "567067343352427"
IG_SIG_KEY = "a86109795736d73c9a94172cd9b736917d7d94ca61c9101164894b3f0d43bef4"

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "7595465023:AAFjt729Da5XlmpuHBvf0y6HvJSjyC1mXiU")
OWNER_ID = int(os.environ.get("TELEGRAM_OWNER_ID", "0"))

USERS_DIR = Path("users")
USERS_DIR.mkdir(exist_ok=True)
SUDO_FILE = Path("sudo_users.json")
PROXY_FILE = Path("proxy_config.json")

(LOGIN_CHOICE, LOGIN_USERNAME, LOGIN_PASSWORD, LOGIN_OTP, 
 LOGIN_SESSION_ID, LOGIN_RESET_LINK, LOGIN_NEW_PASSWORD) = range(7)
(ATTACK_ACCOUNT, ATTACK_CHAT, ATTACK_MESSAGE) = range(7, 10)
(NC_ACCOUNT, NC_CHAT, NC_PREFIX) = range(10, 13)
SESSIONID_USERNAME, SESSIONID_PASSWORD = range(13, 15)
MOBILE_SESSIONID_USERNAME, MOBILE_SESSIONID_PASSWORD = range(15, 17)

sudo_users: Set[int] = set()
user_data_cache: Dict[int, 'UserData'] = {}
ig_clients: Dict[str, Client] = {}
active_tasks: Dict[int, Dict[str, Any]] = {}
stop_flags: Dict[int, asyncio.Event] = {}
pending_logins: Dict[int, Dict[str, Any]] = {}
pid_counter = count(1000)

HEARTS = ["❤️", "🧡", "💛", "💚", "💙", "💜", "🤎", "🖤", "🤍", "💖", "💗", "💓", "💟"]
NC_EMOJIS = ["🔥", "⚡", "💥", "✨", "🌟", "💫", "⭐", "🎯", "💎", "🎪", "🎭", "🎨"]
NC_SUFFIXES = ["『𓆩🦅𓆪』", "⚚🎀࿐", "★彡", "☆彡", "✧", "✦", "༄", "࿐"]


def load_sudo_users() -> Set[int]:
    if SUDO_FILE.exists():
        try:
            with open(SUDO_FILE, 'r') as f:
                return set(json.load(f))
        except:
            pass
    return set()

def save_sudo_users():
    with open(SUDO_FILE, 'w') as f:
        json.dump(list(sudo_users), f)

def is_owner(user_id: int) -> bool:
    return True

def is_sudo(user_id: int) -> bool:
    return True

def load_proxy() -> Optional[str]:
    if PROXY_FILE.exists():
        try:
            with open(PROXY_FILE, 'r') as f:
                data = json.load(f)
                if data.get("enabled"):
                    return data.get("proxy")
        except:
            pass
    return None

def save_proxy(proxy_url: Optional[str]):
    with open(PROXY_FILE, 'w') as f:
        json.dump({"proxy": proxy_url, "enabled": proxy_url is not None}, f)


class UserData:
    def __init__(self, user_id: int):
        self.user_id = user_id
        self.user_dir = USERS_DIR / str(user_id)
        self.user_dir.mkdir(exist_ok=True)
        self.accounts_dir = self.user_dir / "accounts"
        self.accounts_dir.mkdir(exist_ok=True)
        self.prefs_file = self.user_dir / "preferences.json"

        self.prefs: Dict[str, Any] = {
            "default_account": None,
            "paired_accounts": [],
            "switch_interval": 5,
            "threads": 30,
            "delay": 0
        }
        self.accounts: Dict[str, 'InstagramAccount'] = {}
        self.load_prefs()
        self.load_saved_accounts()

    def load_prefs(self):
        if self.prefs_file.exists():
            try:
                with open(self.prefs_file, 'r') as f:
                    self.prefs.update(json.load(f))
            except:
                pass

    def save_prefs(self):
        with open(self.prefs_file, 'w') as f:
            json.dump(self.prefs, f, indent=2)

    def load_saved_accounts(self):
        if not self.accounts_dir.exists():
            return
        for account_dir in self.accounts_dir.iterdir():
            if account_dir.is_dir():
                session_file = account_dir / "session.json"
                if session_file.exists():
                    username = account_dir.name
                    acc = InstagramAccount(username, "", self.accounts_dir)
                    success, _ = acc.restore_session(verify=False)
                    if success:
                        self.accounts[username] = acc
                        logger.info(f"[User {self.user_id}] Loaded @{username}")

    def add_account(self, username: str, account: 'InstagramAccount'):
        self.accounts[username] = account
        if not self.prefs["default_account"]:
            self.prefs["default_account"] = username
            self.save_prefs()

    def remove_account(self, username: str) -> bool:
        if username in self.accounts:
            del self.accounts[username]
            account_dir = self.accounts_dir / username
            if account_dir.exists():
                shutil.rmtree(account_dir)
            if self.prefs["default_account"] == username:
                self.prefs["default_account"] = list(self.accounts.keys())[0] if self.accounts else None
                self.save_prefs()
            return True
        return False


class InstagramAccount:
    def __init__(self, username: str, password: str, accounts_dir: Path):
        self.username = username
        self.password = password
        self.account_dir = accounts_dir / username
        self.account_dir.mkdir(exist_ok=True)
        self.session_file = self.account_dir / "session.json"
        self.client: Optional[Client] = None
        self.pending_otp = None
        self.two_factor_info = None
        self.challenge_info = None

    def _create_client(self) -> Client:
        client = Client()
        client.delay_range = [1, 3]
        proxy = load_proxy()
        if proxy:
            client.set_proxy(proxy)
        return client

    def restore_session(self, verify: bool = True) -> tuple:
        if not self.session_file.exists():
            return False, "No session file"
        try:
            self.client = self._create_client()
            self.client.load_settings(str(self.session_file))
            if verify:
                try:
                    self.client.get_timeline_feed()
                except Exception:
                    pass
            return True, "Session restored"
        except Exception as e:
            self.client = None
            return False, str(e)

    def ensure_session(self) -> bool:
        if self.client:
            try:
                self.client.get_timeline_feed()
                return True
            except Exception:
                pass
        success, _ = self.restore_session(verify=False)
        return success

    def login(self, verification_code: Optional[str] = None) -> tuple:
        self.client = self._create_client()
        try:
            if verification_code:
                self.client.login(self.username, self.password, verification_code=verification_code)
            else:
                self.client.login(self.username, self.password)
            self.client.dump_settings(str(self.session_file))
            return True, "Logged in successfully"
        except TwoFactorRequired as e:
            self.two_factor_info = e
            return False, "OTP_REQUIRED"
        except ChallengeRequired as e:
            self.challenge_info = True
            try:
                challenge_url = self.client.last_json.get('challenge', {}).get('api_path') if self.client else None
                if challenge_url:
                    try:
                        if self.client:
                            self.client.challenge_resolve(self.client.last_json)
                        return False, "CHALLENGE_EMAIL_SENT"
                    except:
                        pass
                return False, "CHALLENGE_REQUIRED"
            except:
                return False, "CHALLENGE_REQUIRED"
        except Exception as e:
            err = str(e).lower()
            if "checkpoint" in err or "challenge" in err:
                self.challenge_info = True
                if "email" in err or "send" in err:
                    return False, "CHALLENGE_EMAIL_REQUIRED"
                return False, "CHALLENGE_REQUIRED"
            if "ip" in err or "block" in err:
                return False, "IP_BLOCKED"
            if "email" in err or "send you" in err:
                self.challenge_info = True
                return False, "CHALLENGE_EMAIL_REQUIRED"
            if "app" in err and "approval" in err:
                return False, "APP_APPROVAL_REQUIRED"
            return False, str(e)

    def request_challenge_code(self, choice: int = 1) -> tuple:
        try:
            if not self.client:
                self.client = self._create_client()
            last_json = getattr(self.client, 'last_json', {})
            if last_json and self.client:
                self.client.challenge_resolve(last_json)
            return True, "Code sent! Check your email/SMS."
        except Exception as e:
            return False, str(e)

    def submit_challenge_code(self, code: str) -> tuple:
        try:
            if not self.client:
                return False, "No active session"
            self.client.login(self.username, self.password, verification_code=code)
            self.client.dump_settings(str(self.session_file))
            return True, "Challenge verified!"
        except Exception as e:
            return False, str(e)

    def login_with_otp(self, otp: str) -> tuple:
        try:
            if self.challenge_info:
                return self.submit_challenge_code(otp)
            elif self.two_factor_info and self.client:
                self.client.login(self.username, self.password, verification_code=otp)
            elif self.client:
                self.client.login(self.username, self.password, verification_code=otp)
            else:
                return False, "No active client session"
            if self.client:
                self.client.dump_settings(str(self.session_file))
            return True, "Logged in with OTP"
        except Exception as e:
            return False, str(e)

    def login_with_session_id(self, session_id: str) -> tuple:
        try:
            self.client = self._create_client()
            self.client.login_by_sessionid(session_id)
            if self.client.username:
                self.username = self.client.username
            self.client.dump_settings(str(self.session_file))
            return True, f"Logged in as @{self.username}"
        except Exception as e:
            self.client = None
            return False, str(e)

    def save_session(self):
        if self.client:
            self.client.dump_settings(str(self.session_file))

    def get_session_id(self) -> Optional[str]:
        try:
            if self.client:
                settings = self.client.get_settings()
                auth = settings.get('authorization_data', {})
                return auth.get('sessionid') or settings.get('cookies', {}).get('sessionid')
        except:
            pass
        return None

    def get_direct_threads(self, amount: int = 10) -> List[Any]:
        try:
            if not self.client:
                self.ensure_session()
            if self.client:
                return self.client.direct_threads(amount=amount)
            return []
        except Exception as e:
            logger.error(f"Error getting threads: {e}")
            self.ensure_session()
            try:
                if self.client:
                    return self.client.direct_threads(amount=amount)
            except:
                pass
            return []

    def send_message(self, thread_id: str, message: str) -> bool:
        try:
            if not self.client:
                self.ensure_session()
            if self.client:
                self.client.direct_send(message, thread_ids=[int(thread_id)])
                return True
            return False
        except Exception as e:
            logger.error(f"Send message error: {e}")
            return False

    def change_thread_title(self, thread_id: str, title: str) -> bool:
        try:
            if not self.client:
                self.ensure_session()
            if self.client:
                self.client.private_request(
                    f"direct_v2/threads/{thread_id}/update_title/",
                    {"title": title}
                )
                return True
            return False
        except Exception as e:
            logger.error(f"Change title error: {e}")
            return False


class SessionExtractor:
    def __init__(self):
        self.instagram_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "X-IG-App-ID": "936619743392459",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": "https://www.instagram.com/"
        }

    async def extract(self, username: str, password: str) -> dict:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get("https://www.instagram.com/accounts/login/") as login_page_response:
                    login_page_text = await login_page_response.text()

                csrf_token = None
                for cookie in login_page_response.cookies.values():
                    if cookie.key == 'csrftoken':
                        csrf_token = cookie.value
                        break

                if not csrf_token:
                    csrf_match = re.search(r'"csrf_token":"([^"]+)"', login_page_text)
                    if csrf_match:
                        csrf_token = csrf_match.group(1)
                    else:
                        return {"status": "error", "message": "Could not get CSRF token"}

                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "X-CSRFToken": csrf_token,
                    "X-IG-App-ID": "936619743392459",
                    "Referer": "https://www.instagram.com/accounts/login/",
                    "X-Requested-With": "XMLHttpRequest"
                }

                login_data = {
                    "username": username,
                    "enc_password": "#PWD_INSTAGRAM:0:" + str(int(time.time())) + ":" + password,
                    "queryParams": "{}",
                    "optIntoOneTap": "false"
                }

                async with session.post(
                    "https://www.instagram.com/accounts/login/ajax/",
                    headers=headers,
                    data=login_data
                ) as response:
                    response_data = await response.json()

                    if response_data.get("authenticated"):
                        session_id = None
                        for cookie in response.cookies.values():
                            if cookie.key == 'sessionid':
                                session_id = cookie.value
                                break
                        if not session_id:
                            return {"status": "error", "message": "No session ID found in cookies"}
                        return {"status": "success", "session_id": session_id, "username": username}

                    elif response_data.get("two_factor_required"):
                        return {"status": "2fa", "message": "2FA required"}

                    elif response_data.get("checkpoint_required") or response_data.get("checkpoint_url"):
                        checkpoint_url = response_data.get("checkpoint_url")
                        return {
                            "status": "checkpoint",
                            "message": "Checkpoint required",
                            "checkpoint_url": "https://www.instagram.com" + checkpoint_url if checkpoint_url else None
                        }

                    else:
                        error_msg = response_data.get("message", "Unknown error occurred")
                        return {"status": "error", "message": error_msg}

        except aiohttp.ClientError as e:
            return {"status": "error", "message": f"Network error: {str(e)}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}


class MobileAPILogin:
    def __init__(self):
        self.device_id = str(uuid.uuid4())
        self.phone_id = str(uuid.uuid4())
        self.uuid = str(uuid.uuid4())
        self.android_id = f"android-{hashlib.md5(self.device_id.encode()).hexdigest()[:16]}"
        self.headers = {
            "User-Agent": IG_USER_AGENT,
            "X-IG-App-ID": IG_APP_ID,
            "X-IG-Device-ID": self.device_id,
            "X-IG-Android-ID": self.android_id,
            "X-IG-Device-Locale": "en_US",
            "X-IG-App-Locale": "en_US",
            "X-IG-Mapped-Locale": "en_US",
            "X-IG-Connection-Type": "WIFI",
            "X-IG-Capabilities": "3brTvwE=",
            "Accept-Language": "en-US",
            "Accept-Encoding": "gzip, deflate",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        }
        self.challenge_url: Optional[str] = None
        self.cookies: Dict[str, str] = {}

    def generate_signature(self, data: str) -> str:
        return hashlib.sha256((IG_SIG_KEY + data).encode()).hexdigest()

    async def login(self, username: str, password: str) -> dict:
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                sync_resp = await client.post(
                    "https://i.instagram.com/api/v1/qe/sync/",
                    headers=self.headers,
                    data={"id": self.uuid, "experiments": "ig_android_progressive_compression,ig_android_device_detection"}
                )
                csrf = sync_resp.cookies.get("csrftoken") or "missing"
                self.cookies = dict(sync_resp.cookies)

                if csrf:
                    self.headers["X-CSRFToken"] = csrf

                login_data = {
                    "jazoest": str(int(time.time() * 1000)),
                    "country_codes": '[{"country_code":"1","source":["default"]}]',
                    "phone_id": self.phone_id,
                    "enc_password": f"#PWD_INSTAGRAM:0:{int(time.time())}:{password}",
                    "username": username,
                    "adid": str(uuid.uuid4()),
                    "guid": self.uuid,
                    "device_id": self.android_id,
                    "google_tokens": "[]",
                    "login_attempt_count": "0",
                }

                response = await client.post(
                    "https://i.instagram.com/api/v1/accounts/login/",
                    headers=self.headers,
                    data=login_data,
                    cookies=self.cookies
                )

                result = response.json()
                self.cookies.update(dict(response.cookies))

                if result.get("logged_in_user"):
                    session_id = response.cookies.get("sessionid")
                    user_info = result.get("logged_in_user", {})
                    return {
                        "status": "success",
                        "session_id": session_id,
                        "username": user_info.get("username", username),
                        "user_id": user_info.get("pk"),
                        "cookies": dict(response.cookies)
                    }
                elif result.get("two_factor_required"):
                    return {
                        "status": "2fa",
                        "two_factor_info": result.get("two_factor_info"),
                        "message": "2FA required"
                    }
                elif result.get("challenge"):
                    self.challenge_url = result.get("challenge", {}).get("api_path")
                    challenge_sent = await self._request_challenge_code(client)
                    if challenge_sent:
                        return {"status": "challenge", "message": "Verification code sent to your email/phone. Enter the code."}
                    return {"status": "checkpoint", "message": "Challenge required but couldn't send code. Try /sessionid"}
                elif result.get("checkpoint_url"):
                    return {"status": "checkpoint", "message": "Checkpoint required. Try /sessionid login instead."}
                else:
                    msg = result.get("message", "Login failed")
                    if "password" in str(msg).lower():
                        msg = "Incorrect password or username"
                    return {"status": "error", "message": msg}

        except Exception as e:
            return {"status": "error", "message": str(e)}

    async def _request_challenge_code(self, client: httpx.AsyncClient) -> bool:
        if not self.challenge_url:
            return False
        try:
            response = await client.get(
                f"https://i.instagram.com{self.challenge_url}",
                headers=self.headers,
                cookies=self.cookies
            )
            result = response.json()
            step_name = result.get("step_name", "")

            if step_name in ["select_verify_method", "verify_email", "verify_phone"]:
                choice = 1
                response = await client.post(
                    f"https://i.instagram.com{self.challenge_url}",
                    headers=self.headers,
                    data={"choice": str(choice)},
                    cookies=self.cookies
                )
                return True
            return False
        except:
            return False

    async def verify_challenge_code(self, code: str) -> dict:
        if not self.challenge_url:
            return {"status": "error", "message": "No challenge pending"}
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"https://i.instagram.com{self.challenge_url}",
                    headers=self.headers,
                    data={"security_code": code},
                    cookies=self.cookies
                )
                result = response.json()

                if result.get("logged_in_user"):
                    session_id = response.cookies.get("sessionid")
                    return {
                        "status": "success",
                        "session_id": session_id,
                        "username": result.get("logged_in_user", {}).get("username")
                    }
                else:
                    return {"status": "error", "message": result.get("message", "Code verification failed")}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    async def login_2fa(self, username: str, code: str, two_factor_info: dict) -> dict:
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                data = {
                    "username": username,
                    "verification_code": code,
                    "two_factor_identifier": two_factor_info.get("two_factor_identifier"),
                    "trust_this_device": "1",
                    "guid": self.uuid,
                    "device_id": self.android_id,
                }

                response = await client.post(
                    "https://i.instagram.com/api/v1/accounts/two_factor_login/",
                    headers=self.headers,
                    data=data,
                    cookies=self.cookies
                )

                result = response.json()
                if result.get("logged_in_user"):
                    session_id = response.cookies.get("sessionid")
                    return {
                        "status": "success",
                        "session_id": session_id,
                        "username": result.get("logged_in_user", {}).get("username", username)
                    }
                else:
                    return {"status": "error", "message": result.get("message", "2FA verification failed")}
        except Exception as e:
            return {"status": "error", "message": str(e)}


class MobileSessionExtractor:
    """Mobile API Session Extractor using aiohttp - runs on mobile API not cloud"""

    def __init__(self):
        self.instagram_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "X-IG-App-ID": "936619743392459",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": "https://www.instagram.com/"
        }

    async def extract_session_id(self, username: str, password: str) -> dict:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get("https://www.instagram.com/accounts/login/") as login_page_response:
                    login_page_text = await login_page_response.text()

                csrf_token = None
                for cookie in login_page_response.cookies.values():
                    if cookie.key == 'csrftoken':
                        csrf_token = cookie.value
                        break

                if not csrf_token:
                    csrf_match = re.search(r'"csrf_token":"([^"]+)"', login_page_text)
                    if csrf_match:
                        csrf_token = csrf_match.group(1)
                    else:
                        return {"status": "error", "message": "Could not get CSRF token"}

                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "X-CSRFToken": csrf_token,
                    "X-IG-App-ID": "936619743392459",
                    "Referer": "https://www.instagram.com/accounts/login/",
                    "X-Requested-With": "XMLHttpRequest"
                }

                login_data = {
                    "username": username,
                    "enc_password": f"#PWD_INSTAGRAM:0:{int(time.time())}:{password}",
                    "queryParams": "{}",
                    "optIntoOneTap": "false"
                }

                async with session.post(
                    "https://www.instagram.com/accounts/login/ajax/",
                    headers=headers,
                    data=login_data
                ) as response:
                    response_data = await response.json()

                    if response_data.get("authenticated"):
                        session_id = None
                        for cookie in response.cookies.values():
                            if cookie.key == 'sessionid':
                                session_id = cookie.value
                                break
                        if not session_id:
                            return {"status": "error", "message": "No session ID found in cookies"}
                        return {"status": "success", "session_id": session_id, "username": username}

                    elif response_data.get("two_factor_required"):
                        return {"status": "2fa_required", "message": "Two-factor authentication required"}

                    elif response_data.get("checkpoint_required"):
                        checkpoint_url = response_data.get("checkpoint_url")
                        return {
                            "status": "checkpoint_required",
                            "message": "Checkpoint required",
                            "checkpoint_url": f"https://www.instagram.com{checkpoint_url}" if checkpoint_url else None
                        }

                    else:
                        error_msg = response_data.get("message", "Unknown error occurred")
                        return {"status": "failed", "message": error_msg}

        except aiohttp.ClientError as e:
            return {"status": "network_error", "message": str(e)}
        except Exception as e:
            return {"status": "error", "message": str(e)}


def get_user_data(user_id: int) -> UserData:
    if user_id not in user_data_cache:
        user_data_cache[user_id] = UserData(user_id)
    return user_data_cache[user_id]


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id

    loading_msg = await update.message.reply_text("𝐅𝐈𝐑𝐌𝐖𝐀𝐑𝐄 𝟐.𝟎 𝐈𝐒 𝐋𝐎𝐀𝐃𝐈𝐍𝐆")

    animations = [
        "▓░░░░░░░░░ 10%",
        "▓▓▓░░░░░░░ 30%",
        "▓▓▓▓▓░░░░░ 50%",
        "▓▓▓▓▓▓▓░░░ 70%",
        "▓▓▓▓▓▓▓▓▓░ 90%",
        "▓▓▓▓▓▓▓▓▓▓ 100%"
    ]

    for anim in animations:
        await asyncio.sleep(0.3)
        try:
            await loading_msg.edit_text(f"𝐅𝐈𝐑𝐌𝐖𝐀𝐑𝐄 𝟐.𝟎 𝐈𝐒 𝐋𝐎𝐀𝐃𝐈𝐍𝐆\n\n{anim}")
        except:
            pass

    await asyncio.sleep(0.5)

    welcome_text = """
✨ Welcome to 𝐓𝐇𝐄 𝐔𝐋𝐓𝐑𝐀 𝐇𝐘𝐏𝐄𝐑 𝐁𝐎𝐓 ⚡

🔒 Your data is private - only YOU can see your accounts!

Type /help to see available commands
"""
    await loading_msg.edit_text(welcome_text)
    get_user_data(user_id)


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    help_text = """
🌟 *Available commands:* 🌟
━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/help ⚡ - Show this help
/login 📱 - Login to Instagram account
/viewmyac 👀 - View your saved accounts
/setig 🔄 <number> - Set default account
/pair 📦 ig1-ig2 - Create account pair for rotation
/unpair ✨ - Unpair accounts
/switch 🔁 <min> - Set switch interval (5+ min)
/threads 🔢 <1-100> - Set number of threads
/viewpref ⚙️ - View preferences
/nc 🪡 - Fast Name Change (Async)
/attack 💥 - Start sending messages
/stop 🔴 <pid/all> - Stop tasks
/task 📋 - View ongoing tasks
/logout 📤 <username> - Logout and remove account
/kill 🟠 - Kill active login session
/sessionid 🔑 - Extract session ID (Web)
/mobilesession 📱 - Extract session ID (Mobile API)

👑 *OWNER COMMANDS:*
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
/sudo 👤 <user_id> - Add sudo user
/unsudo ❌ <user_id> - Remove sudo user
/viewsudo 📋 - View all sudo users
/setproxy 🌐 - Set proxy for IP issues

━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚡ *HYPER ULTRA SPAMMING BOT* ⚡
"""
    await update.message.reply_text(help_text, parse_mode="Markdown")


async def login_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [
        [InlineKeyboardButton("⭐ Session ID (RECOMMENDED)", callback_data="login_session")],
        [InlineKeyboardButton("🤖 Mobile API Login", callback_data="login_mobile")],
        [InlineKeyboardButton("📱 Username & Password", callback_data="login_userpass")],
        [InlineKeyboardButton("🔗 Reset/Login Link", callback_data="login_link")],
        [InlineKeyboardButton("❌ Cancel", callback_data="login_cancel")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await update.message.reply_text(
        "📱 *LOGIN TO INSTAGRAM*\n\n"
        "Choose your login method:\n\n"
        "⭐ *Session ID (HIGHLY RECOMMENDED)*\n"
        "   ✅ Most reliable method\n"
        "   ✅ Bypasses checkpoint issues\n"
        "   ✅ No 2FA problems\n"
        "   ✅ Works with all accounts\n\n"
        "🤖 *Mobile API* - Uses Android app method\n"
        "📱 *Username/Password* - Direct login",
        reply_markup=reply_markup,
        parse_mode="Markdown"
    )
    return LOGIN_CHOICE


async def login_button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    if query.data == "login_cancel":
        await query.edit_message_text("❌ Login cancelled.")
        return ConversationHandler.END

    elif query.data == "login_userpass":
        await query.edit_message_text("📱 Enter your Instagram *username*:", parse_mode="Markdown")
        return LOGIN_USERNAME

    elif query.data == "login_mobile":
        context.user_data['login_method'] = 'mobile'
        await query.edit_message_text("🤖 *Mobile API Login*\n\nEnter your Instagram *username*:", parse_mode="Markdown")
        return LOGIN_USERNAME

    elif query.data == "login_session":
        await query.edit_message_text(
            "⭐ *SESSION ID LOGIN (RECOMMENDED)*\n\n"
            "Paste your Instagram session ID:\n\n"
            "💡 *How to get Session ID:*\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "1️⃣ Login to Instagram in browser\n"
            "2️⃣ Press F12 (Developer Tools)\n"
            "3️⃣ Go to Application → Cookies\n"
            "4️⃣ Click on instagram.com\n"
            "5️⃣ Find 'sessionid' and copy the value\n\n"
            "🔥 *Or use /sessionid command to extract automatically!*\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "✅ This method bypasses all checkpoint issues!",
            parse_mode="Markdown"
        )
        return LOGIN_SESSION_ID

    elif query.data == "login_link":
        await query.edit_message_text(
            "🔗 *Reset/Login Link*\n\n"
            "Paste your Instagram reset or login link:\n\n"
            "• If login link: Will log in directly\n"
            "• If reset link: Will ask for new password",
            parse_mode="Markdown"
        )
        return LOGIN_RESET_LINK

    return ConversationHandler.END


async def login_username(update: Update, context: ContextTypes.DEFAULT_TYPE):
    username = update.message.text.strip().lstrip('@')
    context.user_data['ig_username'] = username
    await update.message.reply_text("🔒 Enter your *password*:", parse_mode="Markdown")
    return LOGIN_PASSWORD


async def login_password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    password = update.message.text
    username = context.user_data.get('ig_username')
    login_method = context.user_data.get('login_method', 'default')

    try:
        await update.message.delete()
    except:
        pass

    msg = await update.message.reply_text(f"🔄 Logging in as @{username}...")

    if login_method == 'mobile':
        mobile_api = MobileAPILogin()
        result = await mobile_api.login(username, password)

        if result["status"] == "success":
            user_data = get_user_data(user_id)
            account = InstagramAccount(username, password, user_data.accounts_dir)
            session_id = result.get("session_id")
            if session_id:
                success, _ = account.login_with_session_id(session_id)
                if success:
                    user_data.add_account(username, account)
                    await msg.edit_text(f"✅ Logged in as @{username} via Mobile API!")
                else:
                    await msg.edit_text(f"✅ Got session but failed to save. Session ID:\n`{session_id}`", parse_mode="Markdown")
            else:
                await msg.edit_text("❌ No session ID in response")
            return ConversationHandler.END
        elif result["status"] == "2fa":
            context.user_data['two_factor_info'] = result.get('two_factor_info')
            context.user_data['mobile_api'] = mobile_api
            context.user_data['password'] = password
            pending_logins[user_id] = {'username': username, 'password': password}
            await msg.edit_text("📲 Enter your 2FA code:")
            return LOGIN_OTP
        elif result["status"] == "challenge":
            context.user_data['mobile_api'] = mobile_api
            context.user_data['password'] = password
            context.user_data['challenge_mode'] = True
            pending_logins[user_id] = {'username': username, 'password': password, 'mobile_api': mobile_api}
            await msg.edit_text(
                "📧 *Verification Required*\n\n"
                "Instagram sent a code to your email/phone.\n"
                "Enter the verification code:",
                parse_mode="Markdown"
            )
            return LOGIN_OTP
        elif result["status"] == "checkpoint":
            await msg.edit_text(
                "❌ *Checkpoint Required*\n\n"
                "Instagram requires verification. Try:\n"
                "1. Login on browser first and complete verification\n"
                "2. Use /sessionid to login with session ID\n"
                "3. Use /setproxy to set a proxy",
                parse_mode="Markdown"
            )
            return ConversationHandler.END
        else:
            await msg.edit_text(f"❌ Login failed: {result['message']}\n\n💡 Try /sessionid to login with Session ID instead.")
            return ConversationHandler.END

    user_data = get_user_data(user_id)
    account = InstagramAccount(username, password, user_data.accounts_dir)
    pending_logins[user_id] = {'username': username, 'password': password, 'account': account}

    success, message = account.login()

    if success:
        user_data.add_account(username, account)
        if user_id in pending_logins:
            del pending_logins[user_id]
        await msg.edit_text(f"✅ Logged in as @{username}!")
        return ConversationHandler.END
    elif message == "OTP_REQUIRED":
        await msg.edit_text("📲 2FA is enabled. Enter your OTP code:")
        return LOGIN_OTP
    elif message == "EMAIL_CODE_SENT" or message == "CHALLENGE_EMAIL_SENT":
        await msg.edit_text(
            "📧 *Verification Required*\n\n"
            "Instagram sent a verification code to your email/phone.\n"
            "Enter the code when you receive it:",
            parse_mode="Markdown"
        )
        return LOGIN_OTP
    elif message == "CHALLENGE_EMAIL_REQUIRED" or message == "CHALLENGE_REQUIRED":
        await msg.edit_text(
            "📧 *Email/SMS Verification Required*\n\n"
            "Instagram needs to verify it's you.\n"
            "A code has been sent to your email or phone.\n\n"
            "Enter the verification code:",
            parse_mode="Markdown"
        )
        return LOGIN_OTP
    elif message == "APP_APPROVAL_REQUIRED":
        await msg.edit_text(
            "📱 *App Approval Required*\n\n"
            "Instagram requires you to approve this login from your app.\n\n"
            "1. Open Instagram app on your phone\n"
            "2. Check for 'Was This You?' notification\n"
            "3. Tap 'This Was Me' to approve\n"
            "4. Try /login again after approving\n\n"
            "Or use /sessionid to login with Session ID.",
            parse_mode="Markdown"
        )
        if user_id in pending_logins:
            del pending_logins[user_id]
        return ConversationHandler.END
    elif message == "IP_BLOCKED":
        await msg.edit_text(
            "🚫 *IP Blocked*\n\n"
            "Instagram has blocked this IP address.\n\n"
            "Solutions:\n"
            "1. Use /setproxy to configure a proxy\n"
            "2. Try /sessionid to login with Session ID\n"
            "3. Wait a few hours and try again",
            parse_mode="Markdown"
        )
        if user_id in pending_logins:
            del pending_logins[user_id]
        return ConversationHandler.END
    else:
        if user_id in pending_logins:
            del pending_logins[user_id]
        await msg.edit_text(f"❌ Login failed: {message}\n\n💡 Try /sessionid to login with Session ID instead.")
        return ConversationHandler.END


async def login_otp(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    otp = update.message.text.strip()
    username = context.user_data.get('ig_username')

    msg = await update.message.reply_text("🔄 Verifying code...")

    if context.user_data and 'mobile_api' in context.user_data:
        mobile_api = context.user_data['mobile_api']
        challenge_mode = context.user_data.get('challenge_mode', False)

        if challenge_mode:
            result = await mobile_api.verify_challenge_code(otp)
        else:
            two_factor_info = context.user_data.get('two_factor_info', {})
            result = await mobile_api.login_2fa(username, otp, two_factor_info)

        if result["status"] == "success":
            user_data = get_user_data(user_id)
            password = context.user_data.get('password', '')
            actual_username = result.get('username', username)
            account = InstagramAccount(actual_username, password, user_data.accounts_dir)
            session_id = result.get("session_id")
            if session_id:
                success, _ = account.login_with_session_id(session_id)
                if success:
                    user_data.add_account(actual_username, account)
            await msg.edit_text(f"✅ Logged in as @{actual_username}!")
        else:
            await msg.edit_text(f"❌ Verification failed: {result['message']}")

        context.user_data.pop('challenge_mode', None)
        context.user_data.pop('mobile_api', None)
        if user_id in pending_logins:
            del pending_logins[user_id]
        return ConversationHandler.END

    if user_id not in pending_logins:
        await msg.edit_text("❌ No pending login session. Use /login again.")
        return ConversationHandler.END

    login_data = pending_logins[user_id]
    account = login_data.get('account')

    if not account:
        await msg.edit_text("❌ Session error. Use /login again.")
        del pending_logins[user_id]
        return ConversationHandler.END

    success, message = account.login_with_otp(otp)

    if success:
        user_data = get_user_data(user_id)
        user_data.add_account(account.username, account)
        del pending_logins[user_id]
        await msg.edit_text(f"✅ Logged in as @{account.username}!")
    else:
        await msg.edit_text(f"❌ OTP verification failed: {message}")

    return ConversationHandler.END


async def login_session_id(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    session_id = update.message.text.strip()
    chat_id = update.effective_chat.id

    try:
        await update.message.delete()
    except:
        pass

    msg = await context.bot.send_message(chat_id, "🔄 Logging in with Session ID...")

    user_data = get_user_data(user_id)
    
    temp_account = InstagramAccount("temp_session", "", user_data.accounts_dir)
    success, message = temp_account.login_with_session_id(session_id)

    if success and temp_account.client:
        actual_username = temp_account.client.username or temp_account.username
        
        if actual_username and actual_username != "temp_session":
            temp_dir = user_data.accounts_dir / "temp_session"
            if temp_dir.exists():
                shutil.rmtree(temp_dir)
            
            account = InstagramAccount(actual_username, "", user_data.accounts_dir)
            account.client = temp_account.client
            account.client.dump_settings(str(account.session_file))
            user_data.add_account(actual_username, account)
            
            logger.info(f"[User {user_id}] Session ID login: @{actual_username}")
            await msg.edit_text(f"✅ Logged in as @{actual_username}!")
        else:
            temp_dir = user_data.accounts_dir / "temp_session"
            if temp_dir.exists():
                shutil.rmtree(temp_dir)
            await msg.edit_text("❌ Login succeeded but couldn't get username. Try again.")
    else:
        temp_dir = user_data.accounts_dir / "temp_session"
        if temp_dir.exists():
            shutil.rmtree(temp_dir)
        await msg.edit_text(f"❌ Login failed: {message}")

    return ConversationHandler.END


async def login_reset_link(update: Update, context: ContextTypes.DEFAULT_TYPE):
    link = update.message.text.strip()

    if "instagram.com" not in link:
        await update.message.reply_text("❌ Invalid Instagram link!")
        return ConversationHandler.END

    context.user_data['reset_link'] = link
    await update.message.reply_text(
        "🔒 Enter your *new password*:",
        parse_mode="Markdown"
    )
    return LOGIN_NEW_PASSWORD


async def login_new_password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        await update.message.delete()
    except:
        pass

    await update.message.reply_text(
        "❌ Reset link login not fully implemented.\n"
        "Please use /login with username/password or /sessionid."
    )
    return ConversationHandler.END


async def login_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id in pending_logins:
        del pending_logins[user_id]
    await update.message.reply_text("❌ Login cancelled.")
    return ConversationHandler.END


async def viewmyac(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    user_data = get_user_data(user_id)

    if not user_data.accounts:
        await update.message.reply_text("❌ No accounts saved. Use /login to add one.")
        return

    text = "👀 *YOUR ACCOUNTS*\n\n"
    default = user_data.prefs.get("default_account")

    for i, username in enumerate(user_data.accounts.keys(), 1):
        marker = "⭐" if username == default else "  "
        text += f"{i}. {marker} @{username}\n"

    text += f"\n⭐ = Default account\nUse /setig <number> to change default"
    await update.message.reply_text(text, parse_mode="Markdown")


async def setig(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    user_data = get_user_data(user_id)

    if not context.args:
        await update.message.reply_text("🔄 Usage: /setig <number>")
        return

    try:
        idx = int(context.args[0]) - 1
        accounts = list(user_data.accounts.keys())
        if 0 <= idx < len(accounts):
            username = accounts[idx]
            user_data.prefs["default_account"] = username
            user_data.save_prefs()
            await update.message.reply_text(f"✅ Default account set to @{username}")
        else:
            await update.message.reply_text("❌ Invalid number!")
    except ValueError:
        await update.message.reply_text("❌ Enter a valid number!")


async def pair(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    user_data = get_user_data(user_id)

    if not context.args:
        await update.message.reply_text("📦 Usage: /pair ig1-ig2")
        return

    parts = context.args[0].split('-')
    if len(parts) != 2:
        await update.message.reply_text("❌ Format: /pair ig1-ig2")
        return

    ig1, ig2 = parts[0].lstrip('@'), parts[1].lstrip('@')

    if ig1 not in user_data.accounts or ig2 not in user_data.accounts:
        await update.message.reply_text("❌ Both accounts must be logged in!")
        return

    user_data.prefs["paired_accounts"] = [ig1, ig2]
    user_data.save_prefs()
    await update.message.reply_text(f"✅ Paired @{ig1} with @{ig2}")


async def unpair(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    user_data = get_user_data(user_id)

    user_data.prefs["paired_accounts"] = []
    user_data.save_prefs()
    await update.message.reply_text("✅ Accounts unpaired!")


async def switch(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    user_data = get_user_data(user_id)

    if not context.args:
        await update.message.reply_text(f"🔁 Current interval: {user_data.prefs['switch_interval']} minutes\nUsage: /switch <minutes>")
        return

    try:
        minutes = int(context.args[0])
        if minutes < 5:
            await update.message.reply_text("❌ Minimum interval is 5 minutes!")
            return
        user_data.prefs["switch_interval"] = minutes
        user_data.save_prefs()
        await update.message.reply_text(f"✅ Switch interval set to {minutes} minutes")
    except ValueError:
        await update.message.reply_text("❌ Enter a valid number!")


async def threads(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    user_data = get_user_data(user_id)

    if not context.args:
        await update.message.reply_text(f"🔢 Current threads: {user_data.prefs['threads']}\nUsage: /threads <1-100>")
        return

    try:
        num = int(context.args[0])
        if num < 1 or num > 100:
            await update.message.reply_text("❌ Threads must be between 1 and 100!")
            return
        user_data.prefs["threads"] = num
        user_data.save_prefs()
        await update.message.reply_text(f"✅ Threads set to {num}")
    except ValueError:
        await update.message.reply_text("❌ Enter a valid number!")


async def viewpref(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    user_data = get_user_data(user_id)

    text = "⚙️ *YOUR PREFERENCES*\n\n"
    text += f"📱 Default Account: @{user_data.prefs.get('default_account') or 'None'}\n"
    text += f"📦 Paired: {', '.join(user_data.prefs.get('paired_accounts', [])) or 'None'}\n"
    text += f"🔁 Switch Interval: {user_data.prefs.get('switch_interval', 5)} min\n"
    text += f"🔢 Threads: {user_data.prefs.get('threads', 30)}\n"
    text += f"⏱️ Delay: {user_data.prefs.get('delay', 0)}s"

    await update.message.reply_text(text, parse_mode="Markdown")


async def attack_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    user_data = get_user_data(user_id)

    if not user_data.accounts:
        await update.message.reply_text("❌ No accounts. Use /login first.")
        return ConversationHandler.END

    text = "💥 *SELECT ACCOUNT FOR ATTACK*\n\n"
    for i, username in enumerate(user_data.accounts.keys(), 1):
        text += f"{i}. @{username}\n"
    text += "\nReply with the number:"

    await update.message.reply_text(text, parse_mode="Markdown")
    return ATTACK_ACCOUNT


async def attack_account(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    user_data = get_user_data(user_id)

    try:
        idx = int(update.message.text.strip()) - 1
        accounts = list(user_data.accounts.keys())
        if 0 <= idx < len(accounts):
            username = accounts[idx]
            context.user_data['attack_account'] = username
            account = user_data.accounts[username]

            msg = await update.message.reply_text("🔄 Loading chats...")
            threads_list = account.get_direct_threads(10)

            if not threads_list:
                await msg.edit_text("❌ No chats found.")
                return ConversationHandler.END

            context.user_data['threads'] = threads_list
            text = "💬 *SELECT CHAT*\n\n"
            for i, thread in enumerate(threads_list, 1):
                title = thread.thread_title or "Direct"
                text += f"{i}. {title}\n"
            text += "\nReply with the number:"

            await msg.edit_text(text, parse_mode="Markdown")
            return ATTACK_CHAT
        else:
            await update.message.reply_text("❌ Invalid number!")
            return ConversationHandler.END
    except ValueError:
        await update.message.reply_text("❌ Please enter a valid number!")
        return ConversationHandler.END


async def attack_chat(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        idx = int(update.message.text.strip()) - 1
        threads_list = context.user_data.get('threads', [])

        if 0 <= idx < len(threads_list):
            thread = threads_list[idx]
            context.user_data['attack_thread'] = thread
            await update.message.reply_text(
                f"✅ Selected: *{thread.thread_title or 'Direct'}*\n\n"
                "📝 Now send the message you want to spam:",
                parse_mode="Markdown"
            )
            return ATTACK_MESSAGE
        else:
            await update.message.reply_text("❌ Invalid number!")
            return ConversationHandler.END
    except ValueError:
        await update.message.reply_text("❌ Please enter a valid number!")
        return ConversationHandler.END


async def attack_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    user_data = get_user_data(user_id)
    message = update.message.text

    username = context.user_data.get('attack_account')
    thread = context.user_data.get('attack_thread')
    account = user_data.accounts.get(username)

    if not account or not thread:
        await update.message.reply_text("❌ Error: Session expired. Try again.")
        return ConversationHandler.END

    pid = next(pid_counter)
    stop_flags[pid] = asyncio.Event()

    active_tasks[pid] = {
        "user_id": user_id,
        "type": "attack",
        "account": username,
        "thread": thread.thread_title or "Direct",
        "message": message[:50] + "..." if len(message) > 50 else message
    }

    num_threads = user_data.prefs.get("threads", 30)

    await update.message.reply_text(
        f"🚀 *ATTACK STARTED*\n\n"
        f"📋 PID: `{pid}`\n"
        f"📱 Account: @{username}\n"
        f"💬 Chat: {thread.thread_title or 'Direct'}\n"
        f"🔢 Threads: {num_threads}\n"
        f"📝 Message: {message[:30]}...\n\n"
        f"Use /stop {pid} to stop",
        parse_mode="Markdown"
    )

    asyncio.create_task(run_attack(pid, account, str(thread.id), message, num_threads, stop_flags[pid]))
    return ConversationHandler.END


async def run_attack(pid: int, account: InstagramAccount, thread_id: str, message: str, num_threads: int, stop_event: asyncio.Event):
    count = 0
    errors = 0
    max_errors = 50

    while not stop_event.is_set() and errors < max_errors:
        tasks = []
        for _ in range(num_threads):
            if stop_event.is_set():
                break
            tasks.append(asyncio.to_thread(account.send_message, thread_id, message))

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if r is True:
                    count += 1
                elif isinstance(r, Exception):
                    errors += 1
                    if errors >= max_errors:
                        logger.warning(f"Attack {pid}: Too many errors, stopping")
                        break

    if pid in active_tasks:
        del active_tasks[pid]
    if pid in stop_flags:
        del stop_flags[pid]
    logger.info(f"Attack {pid} stopped. Sent {count} messages, {errors} errors.")


async def nc_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    user_data = get_user_data(user_id)

    if not user_data.accounts:
        await update.message.reply_text("❌ No accounts. Use /login first.")
        return ConversationHandler.END

    text = "🪡 *SELECT ACCOUNT FOR NC (Fast Async)*\n\n"
    for i, username in enumerate(user_data.accounts.keys(), 1):
        text += f"{i}. @{username}\n"
    text += "\nReply with the number:"

    await update.message.reply_text(text, parse_mode="Markdown")
    return NC_ACCOUNT


async def nc_account(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    user_data = get_user_data(user_id)

    try:
        idx = int(update.message.text.strip()) - 1
        accounts = list(user_data.accounts.keys())
        if 0 <= idx < len(accounts):
            username = accounts[idx]
            context.user_data['nc_account'] = username
            account = user_data.accounts[username]

            msg = await update.message.reply_text("🔄 Loading chats...")
            threads_list = account.get_direct_threads(10)

            if not threads_list:
                await msg.edit_text("❌ No chats found.")
                return ConversationHandler.END

            context.user_data['threads'] = threads_list
            text = "💬 *SELECT GROUP CHAT*\n\n"
            for i, thread in enumerate(threads_list, 1):
                title = thread.thread_title or "Direct"
                text += f"{i}. {title}\n"
            text += "\nReply with the number:"

            await msg.edit_text(text, parse_mode="Markdown")
            return NC_CHAT
        else:
            await update.message.reply_text("❌ Invalid!")
            return ConversationHandler.END
    except ValueError:
        await update.message.reply_text("❌ Enter a valid number!")
        return ConversationHandler.END


async def nc_chat(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        idx = int(update.message.text.strip()) - 1
        threads_list = context.user_data.get('threads', [])

        if 0 <= idx < len(threads_list):
            thread = threads_list[idx]
            context.user_data['nc_thread'] = thread
            await update.message.reply_text(
                f"✅ Selected: *{thread.thread_title or 'Direct'}*\n\n"
                "📝 Send the name prefix (will add rotating emojis/suffixes):",
                parse_mode="Markdown"
            )
            return NC_PREFIX
        else:
            await update.message.reply_text("❌ Invalid!")
            return ConversationHandler.END
    except ValueError:
        await update.message.reply_text("❌ Enter a valid number!")
        return ConversationHandler.END


async def nc_prefix(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    user_data = get_user_data(user_id)
    prefix = update.message.text

    username = context.user_data.get('nc_account')
    thread = context.user_data.get('nc_thread')
    account = user_data.accounts.get(username)

    if not account or not thread:
        await update.message.reply_text("❌ Error. Try again.")
        return ConversationHandler.END

    pid = next(pid_counter)
    stop_flags[pid] = asyncio.Event()

    active_tasks[pid] = {
        "user_id": user_id,
        "type": "nc",
        "account": username,
        "thread": thread.thread_title or "Direct",
        "prefix": prefix
    }

    num_tasks = user_data.prefs.get("threads", 5)
    if num_tasks > 10:
        num_tasks = 10

    await update.message.reply_text(
        f"🪡 *FAST NC STARTED (Async)*\n\n"
        f"📋 PID: `{pid}`\n"
        f"📱 Account: @{username}\n"
        f"💬 Chat: {thread.thread_title or 'Direct'}\n"
        f"📝 Prefix: {prefix}\n"
        f"⚡ Async Tasks: {num_tasks}\n\n"
        f"Use /stop {pid} to stop",
        parse_mode="Markdown"
    )

    asyncio.create_task(run_nc_async(pid, account, str(thread.id), prefix, num_tasks, stop_flags[pid]))
    return ConversationHandler.END


async def run_nc_async(pid: int, account: InstagramAccount, thread_id: str, prefix: str, num_tasks: int, stop_event: asyncio.Event):
    """Fast async name changing using Playwright method from DEV2.0"""
    name_counter = count(1)
    used_names: Set[str] = set()
    success_count = 0
    fail_count = 0
    lock = asyncio.Lock()

    session_id = account.get_session_id()
    if not session_id:
        logger.error(f"NC {pid}: Could not get session ID")
        if pid in active_tasks:
            del active_tasks[pid]
        if pid in stop_flags:
            del stop_flags[pid]
        return

    dm_url = f"https://www.instagram.com/direct/t/{thread_id}/"

    def generate_name() -> str:
        while True:
            suffix = random.choice(NC_SUFFIXES)
            num = next(name_counter)
            name = f"{prefix} {suffix}_{num}"
            if name not in used_names:
                used_names.add(name)
                return name

    async def rename_loop(context):
        nonlocal success_count, fail_count
        page = await context.new_page()
        try:
            await page.goto(dm_url, wait_until='domcontentloaded', timeout=600000)
            gear = page.locator('svg[aria-label="Conversation information"]')
            await gear.wait_for(timeout=160000)
            await gear.click()
            await asyncio.sleep(1)
        except Exception as e:
            logger.error(f"Page init failed: {e}")
            async with lock:
                fail_count += 1
            return

        change_btn = page.locator('div[aria-label="Change group name"][role="button"]')
        group_input = page.locator('input[aria-label="Group name"][name="change-group-name"]')
        save_btn = page.locator('div[role="button"]:has-text("Save")')

        while not stop_event.is_set():
            try:
                name = generate_name()
                await change_btn.click()
                await group_input.click(click_count=3)
                await group_input.fill(name)

                disabled = await save_btn.get_attribute("aria-disabled")
                if disabled == "true":
                    async with lock:
                        fail_count += 1
                    continue

                await save_btn.click()
                async with lock:
                    success_count += 1

            except Exception:
                async with lock:
                    fail_count += 1

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True, args=['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage'])

            context = await browser.new_context(
                locale="en-US",
                extra_http_headers={"Referer": "https://www.instagram.com/"},
                viewport=None
            )
            await context.add_cookies([{
                "name": "sessionid",
                "value": session_id,
                "domain": ".instagram.com",
                "path": "/",
                "httpOnly": True,
                "secure": True,
                "sameSite": "None"
            }])

            tasks = [asyncio.create_task(rename_loop(context)) for _ in range(num_tasks)]

            try:
                await asyncio.gather(*tasks)
            except asyncio.CancelledError:
                pass
            finally:
                await browser.close()
    except Exception as e:
        logger.error(f"NC {pid} Playwright error: {e}")

    if pid in active_tasks:
        del active_tasks[pid]
    if pid in stop_flags:
        del stop_flags[pid]
    logger.info(f"NC {pid} stopped. Success: {success_count}, Failed: {fail_count}")


async def stop_task(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id

    if not context.args:
        await update.message.reply_text("🔴 Usage: /stop <pid> or /stop all")
        return

    arg = context.args[0].lower()

    if arg == "all":
        stopped = 0
        for pid, task in list(active_tasks.items()):
            if task["user_id"] == user_id or is_owner(user_id):
                if pid in stop_flags:
                    stop_flags[pid].set()
                    stopped += 1
        await update.message.reply_text(f"🔴 Stopped {stopped} task(s)")
    else:
        try:
            pid = int(arg)
            if pid in active_tasks:
                if active_tasks[pid]["user_id"] == user_id or is_owner(user_id):
                    if pid in stop_flags:
                        stop_flags[pid].set()
                    await update.message.reply_text(f"🔴 Stopped task {pid}")
                else:
                    await update.message.reply_text("❌ Not your task!")
            else:
                await update.message.reply_text("❌ Task not found!")
        except ValueError:
            await update.message.reply_text("❌ Invalid PID!")


async def task(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id

    user_tasks = {pid: t for pid, t in active_tasks.items() 
                  if t["user_id"] == user_id or is_owner(user_id)}

    if not user_tasks:
        await update.message.reply_text("📋 No active tasks.")
        return

    text = "📋 *ACTIVE TASKS*\n\n"
    for pid, t in user_tasks.items():
        text += f"PID: `{pid}` | {t['type'].upper()}\n"
        text += f"  📱 @{t['account']} | 💬 {t['thread']}\n\n"

    await update.message.reply_text(text, parse_mode="Markdown")


async def logout(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    user_data = get_user_data(user_id)

    if not context.args:
        await update.message.reply_text("📤 Usage: /logout <username>")
        return

    username = context.args[0].lstrip('@')

    if user_data.remove_account(username):
        await update.message.reply_text(f"✅ Logged out @{username}")
    else:
        await update.message.reply_text(f"❌ Account @{username} not found!")


async def kill(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id

    if user_id in pending_logins:
        del pending_logins[user_id]
        await update.message.reply_text("🟠 Active login session killed.")
    else:
        await update.message.reply_text("❌ No active login session.")


async def sessionid_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🔑 *SESSION ID EXTRACTOR*\n\n"
        "Enter Instagram username:",
        parse_mode="Markdown"
    )
    return SESSIONID_USERNAME


async def sessionid_username(update: Update, context: ContextTypes.DEFAULT_TYPE):
    username = update.message.text.strip().lstrip('@')
    context.user_data['extract_username'] = username
    await update.message.reply_text("🔒 Enter password:")
    return SESSIONID_PASSWORD


async def sessionid_password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    password = update.message.text
    username = context.user_data.get('extract_username')

    try:
        await update.message.delete()
    except:
        pass

    msg = await update.message.reply_text("🔄 Extracting session ID...")

    extractor = SessionExtractor()
    result = await extractor.extract(username, password)

    if result["status"] == "success":
        await msg.edit_text(
            f"✅ *SESSION ID EXTRACTED*\n\n"
            f"👤 Username: @{result['username']}\n"
            f"🔑 Session ID:\n`{result['session_id']}`\n\n"
            f"⚠️ Keep this secret!\n\n"
            f"💡 Use /login > Session ID to login with this.",
            parse_mode="Markdown"
        )
    elif result["status"] == "2fa":
        await msg.edit_text("❌ 2FA required. Cannot extract via web.")
    elif result["status"] == "checkpoint":
        await msg.edit_text("❌ Checkpoint required. Try on browser first.")
    else:
        await msg.edit_text(f"❌ Error: {result['message']}")

    return ConversationHandler.END


async def mobile_sessionid_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "📱 *MOBILE API SESSION ID EXTRACTOR*\n\n"
        "🔐 This uses Mobile API (not cloud)\n"
        "⚡ Faster & more reliable\n\n"
        "Enter Instagram username:",
        parse_mode="Markdown"
    )
    return MOBILE_SESSIONID_USERNAME


async def mobile_sessionid_username(update: Update, context: ContextTypes.DEFAULT_TYPE):
    username = update.message.text.strip().lstrip('@')
    context.user_data['mobile_extract_username'] = username
    await update.message.reply_text("🔒 Enter password:")
    return MOBILE_SESSIONID_PASSWORD


async def mobile_sessionid_password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    password = update.message.text
    username = context.user_data.get('mobile_extract_username')

    try:
        await update.message.delete()
    except:
        pass

    msg = await update.message.reply_text(
        "🔄 *Initializing Mobile API extraction...*\n"
        "⚡ Establishing secure connection...",
        parse_mode="Markdown"
    )

    extractor = MobileSessionExtractor()
    result = await extractor.extract_session_id(username, password)

    if result["status"] == "success":
        await msg.edit_text(
            f"✅ *MISSION SUCCESS: SESSION ID ACQUIRED*\n\n"
            f"👤 Target: @{result['username']}\n"
            f"🔑 Session ID:\n`{result['session_id']}`\n\n"
            f"⚠️ *SECURITY ALERT:*\n"
            f"• This session ID provides FULL ACCESS\n"
            f"• Handle with extreme caution - DO NOT SHARE\n"
            f"• Change credentials to terminate session\n\n"
            f"💡 Use /login > Session ID to login with this.",
            parse_mode="Markdown"
        )
    elif result["status"] == "2fa_required":
        await msg.edit_text(
            "❌ *ACCESS DENIED*\n\n"
            "🔐 Two-factor authentication detected\n"
            "⚠️ Manual intervention needed",
            parse_mode="Markdown"
        )
    elif result["status"] == "checkpoint_required":
        checkpoint_url = result.get("checkpoint_url", "")
        await msg.edit_text(
            f"❌ *SECURITY CHECKPOINT*\n\n"
            f"🛡️ Instagram defense mechanism activated\n"
            f"⚠️ Complete verification via web interface\n"
            f"🔗 URL: {checkpoint_url}" if checkpoint_url else "",
            parse_mode="Markdown"
        )
    else:
        await msg.edit_text(
            f"❌ *OPERATION FAILED*\n\n"
            f"📛 Error: {result.get('message', 'Unknown error')}\n\n"
            f"⚠️ Possible causes:\n"
            f"• Invalid credentials\n"
            f"• Account lockdown detected\n"
            f"• Temporary connection blacklist",
            parse_mode="Markdown"
        )

    return ConversationHandler.END


async def sudo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id

    if not is_owner(user_id):
        await update.message.reply_text("❌ Owner only command!")
        return

    if not context.args:
        await update.message.reply_text("👤 Usage: /sudo <user_id>")
        return

    try:
        target_id = int(context.args[0])
        sudo_users.add(target_id)
        save_sudo_users()
        await update.message.reply_text(f"✅ Added sudo user: {target_id}")
    except ValueError:
        await update.message.reply_text("❌ Invalid user ID!")


async def unsudo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id

    if not is_owner(user_id):
        await update.message.reply_text("❌ Owner only command!")
        return

    if not context.args:
        await update.message.reply_text("❌ Usage: /unsudo <user_id>")
        return

    try:
        target_id = int(context.args[0])
        sudo_users.discard(target_id)
        save_sudo_users()
        await update.message.reply_text(f"✅ Removed sudo user: {target_id}")
    except ValueError:
        await update.message.reply_text("❌ Invalid user ID!")


async def viewsudo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id

    if not is_owner(user_id):
        await update.message.reply_text("❌ Owner only command!")
        return

    if not sudo_users:
        await update.message.reply_text("📋 No sudo users.")
        return

    text = "📋 *SUDO USERS*\n\n"
    for uid in sudo_users:
        text += f"• `{uid}`\n"
    await update.message.reply_text(text, parse_mode="Markdown")


async def setproxy(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id

    if not is_sudo(user_id):
        await update.message.reply_text("❌ Sudo users only!")
        return

    if not context.args:
        current = load_proxy()
        await update.message.reply_text(
            f"🌐 *PROXY SETUP*\n\n"
            f"Current: `{current or 'None'}`\n\n"
            f"Usage:\n"
            f"/setproxy http://user:pass@host:port\n"
            f"/setproxy none - Remove proxy",
            parse_mode="Markdown"
        )
        return

    proxy = context.args[0]
    if proxy.lower() == "none":
        save_proxy(None)
        await update.message.reply_text("✅ Proxy removed!")
    else:
        save_proxy(proxy)
        await update.message.reply_text(f"✅ Proxy set to:\n`{proxy}`", parse_mode="Markdown")


def main():
    global sudo_users

    if not BOT_TOKEN:
        logger.error("TELEGRAM_BOT_TOKEN environment variable not set!")
        print("❌ Please set TELEGRAM_BOT_TOKEN environment variable")
        print("   You can set it in the Secrets tab in Replit")
        return

    if OWNER_ID == 0:
        logger.warning("TELEGRAM_OWNER_ID not set. Owner commands will be disabled.")

    sudo_users = load_sudo_users()

    application = Application.builder().token(BOT_TOKEN).build()

    login_handler = ConversationHandler(
        entry_points=[CommandHandler("login", login_start)],
        states={
            LOGIN_CHOICE: [CallbackQueryHandler(login_button_handler)],
            LOGIN_USERNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, login_username)],
            LOGIN_PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, login_password)],
            LOGIN_OTP: [MessageHandler(filters.TEXT & ~filters.COMMAND, login_otp)],
            LOGIN_SESSION_ID: [MessageHandler(filters.TEXT & ~filters.COMMAND, login_session_id)],
            LOGIN_RESET_LINK: [MessageHandler(filters.TEXT & ~filters.COMMAND, login_reset_link)],
            LOGIN_NEW_PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, login_new_password)],
        },
        fallbacks=[CommandHandler("cancel", login_cancel)],
    )

    attack_handler = ConversationHandler(
        entry_points=[CommandHandler("attack", attack_start)],
        states={
            ATTACK_ACCOUNT: [MessageHandler(filters.TEXT & ~filters.COMMAND, attack_account)],
            ATTACK_CHAT: [MessageHandler(filters.TEXT & ~filters.COMMAND, attack_chat)],
            ATTACK_MESSAGE: [MessageHandler(filters.TEXT & ~filters.COMMAND, attack_message)],
        },
        fallbacks=[CommandHandler("cancel", login_cancel)],
    )

    nc_handler = ConversationHandler(
        entry_points=[CommandHandler("nc", nc_start)],
        states={
            NC_ACCOUNT: [MessageHandler(filters.TEXT & ~filters.COMMAND, nc_account)],
            NC_CHAT: [MessageHandler(filters.TEXT & ~filters.COMMAND, nc_chat)],
            NC_PREFIX: [MessageHandler(filters.TEXT & ~filters.COMMAND, nc_prefix)],
        },
        fallbacks=[CommandHandler("cancel", login_cancel)],
    )

    sessionid_handler = ConversationHandler(
        entry_points=[CommandHandler("sessionid", sessionid_start)],
        states={
            SESSIONID_USERNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, sessionid_username)],
            SESSIONID_PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, sessionid_password)],
        },
        fallbacks=[CommandHandler("cancel", login_cancel)],
    )

    mobile_sessionid_handler = ConversationHandler(
        entry_points=[CommandHandler("mobilesession", mobile_sessionid_start)],
        states={
            MOBILE_SESSIONID_USERNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, mobile_sessionid_username)],
            MOBILE_SESSIONID_PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, mobile_sessionid_password)],
        },
        fallbacks=[CommandHandler("cancel", login_cancel)],
    )

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(login_handler)
    application.add_handler(attack_handler)
    application.add_handler(nc_handler)
    application.add_handler(sessionid_handler)
    application.add_handler(mobile_sessionid_handler)
    application.add_handler(CommandHandler("viewmyac", viewmyac))
    application.add_handler(CommandHandler("setig", setig))
    application.add_handler(CommandHandler("pair", pair))
    application.add_handler(CommandHandler("unpair", unpair))
    application.add_handler(CommandHandler("switch", switch))
    application.add_handler(CommandHandler("threads", threads))
    application.add_handler(CommandHandler("viewpref", viewpref))
    application.add_handler(CommandHandler("stop", stop_task))
    application.add_handler(CommandHandler("task", task))
    application.add_handler(CommandHandler("logout", logout))
    application.add_handler(CommandHandler("kill", kill))
    application.add_handler(CommandHandler("sudo", sudo))
    application.add_handler(CommandHandler("unsudo", unsudo))
    application.add_handler(CommandHandler("viewsudo", viewsudo))
    application.add_handler(CommandHandler("setproxy", setproxy))

    logger.info("Bot starting...")
    print("🚀 Bot is running! Send /start in Telegram to begin.")
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
