"""
HexStrike - Configuration Loader
Loads API keys and environment variables from .env file
"""

import os
import sys
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:
    os.system("pip3 install python-dotenv --break-system-packages -q")
    from dotenv import load_dotenv

# Load .env from the same directory as this file
ENV_PATH = Path(__file__).parent / ".env"
load_dotenv(dotenv_path=ENV_PATH)

def get_shodan_key():
    key = os.getenv("SHODAN_API_KEY", "").strip()
    if not key:
        print("[config] WARNING: SHODAN_API_KEY not set in .env — Shodan scanning will be skipped.")
    return key

def get_google_api_key():
    key = os.getenv("GOOGLE_API_KEY", "").strip()
    if not key:
        print("[config] WARNING: GOOGLE_API_KEY not set in .env — Google Dorking will be skipped.")
    return key

def get_google_cx():
    cx = os.getenv("GOOGLE_CX", "").strip()
    if not cx:
        print("[config] WARNING: GOOGLE_CX not set in .env — Google Dorking will be skipped.")
    return cx

# Expose all keys as module-level constants
SHODAN_API_KEY   = get_shodan_key()
GOOGLE_API_KEY   = get_google_api_key()
GOOGLE_CX        = get_google_cx()
