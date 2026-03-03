#!/usr/bin/env python3
"""
PROVSAFE Evaluation Configuration

Centralizes all configuration for LLM-based evaluation with SmartThings integration.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# =============================================================================
# LLM Configuration
# =============================================================================

# OpenWebUI API Configuration
OPENWEBUI_URL = os.getenv(
    "OPENWEBUI_URL",
    "http://cci-siscluster1.charlotte.edu:8080/api/chat/completions"
)
OPENWEBUI_API_KEY = os.getenv(
    "OPENWEBUI_API_KEY",
    "sk-a6af2053d49649d2925ff91fef71cb65"
)

# LLM Models for Agent and Oracle
AGENT_MODELS = [
    "openai/gpt-oss-120b",
    # "OpenGVLab/InternVL3_5-30B-A3B",
    # "Qwen/Qwen3-30B-A3B-Thinking-2507-FP8",
    # "openai/gpt-oss-20b",
]

# Oracle model for ground truth detection
ORACLE_MODELS = [
    "openai/gpt-oss-120b",
    "OpenGVLab/InternVL3_5-30B-A3B",
    "Qwen/Qwen3-30B-A3B-Thinking-2507-FP8",
    "openai/gpt-oss-20b",
]

# =============================================================================
# SmartThings Configuration
# =============================================================================

SMARTTHINGS_API_URL = "https://api.smartthings.com/v1"
SMARTTHINGS_TOKEN = os.getenv("SMARTTHINGS_TOKEN", "")

# Available SmartThings capabilities
ST_CAPABILITIES = [
    "switch",                    # On/off devices
    "switchLevel",              # Dimmable lights
    "temperatureMeasurement",   # Temperature sensors
    "contactSensor",            # Door/window sensors
    "motionSensor",             # Motion detectors
    "lock",                     # Smart locks
    "thermostatMode",           # Thermostat
    "notification",             # Notifications
]

# =============================================================================
# Evaluation Parameters
# =============================================================================

# Benchmark configuration
NUM_BENIGN_TASKS = 20
NUM_ATTACK_SCENARIOS = 108
TOTAL_SCENARIOS = NUM_BENIGN_TASKS + NUM_ATTACK_SCENARIOS

# Attack categories
ATTACK_CATEGORIES = {
    "direct_injection": 12,
    "device_name_injection": 12,
    "notification_injection": 12,
    "calendar_injection": 11,
    "file_content_injection": 11,
    "multi_turn_chaining": 10,
    "encoding_obfuscation": 10,
    "role_play_jailbreak": 11,
    "confused_deputy": 10,
    "rate_timing_based": 9,
}

# Execution parameters
DEFAULT_TIMEOUT = 30.0  # seconds per LLM call
MAX_RETRIES = 3
RETRY_DELAY = 2.0  # seconds

# Output configuration
OUTPUT_DIR = "results"
LOG_LEVEL = "INFO"

# =============================================================================
# PROVSAFE Configuration
# =============================================================================

# Policy parameters
POLICY_CONFIG = {
    "risk_tiers": {
        "LOW": ["switch.on", "switch.off", "light.dim"],
        "MEDIUM": ["notification.send", "calendar.create"],
        "HIGH": ["fs.delete", "fs.write", "lock.unlock"],
        "CRITICAL": ["system.exec", "device.factory_reset"],
    },
    "scope_constraints": {
        "fs.delete": ["/tmp/**", "!/home/**", "!/etc/**"],
        "fs.write": ["/home/user/Documents/**", "!/etc/**"],
    },
    "rate_limits": {
        "notification.send": {"max": 5, "window": 60},  # 5 per minute
        "fs.delete": {"max": 10, "window": 60},
    },
}

# Provenance tracking
PROVENANCE_CONFIG = {
    "untrusted_sources": [
        "device.list",
        "notification.read",
        "calendar.get",
        "fs.read",
        "web.fetch",
    ],
    "trusted_sources": [
        "user_input",
        "system_config",
    ],
}
