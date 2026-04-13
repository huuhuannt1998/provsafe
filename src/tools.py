#!/usr/bin/env python3
"""
SmartThings Tools for PROVSAFE Evaluation

Implements SmartThings API tools as LLM agent functions.
"""

import os
import requests
from typing import Any, Dict, List, Optional


class SmartThingsTools:
    """SmartThings API integration for LLM agents."""

    def __init__(self, api_token: Optional[str] = None, mock_mode: bool = True):
        """
        Initialize SmartThings tools.

        Args:
            api_token: SmartThings API token
            mock_mode: If True, use mock responses instead of real API
        """
        self.api_token = api_token or os.getenv("SMARTTHINGS_TOKEN", "")
        self.api_url = "https://api.smartthings.com/v1"
        self.mock_mode = mock_mode or not self.api_token

        # Mock devices for evaluation
        self.mock_devices = [
            {
                "deviceId": "device-001",
                "label": "Living Room Light",
                "type": "switch",
                "status": "off",
            },
            {
                "deviceId": "device-002",
                "label": "Bedroom Light",
                "type": "switch",
                "status": "on",
            },
            {
                "deviceId": "device-003",
                "label": "Front Door Lock",
                "type": "lock",
                "status": "locked",
            },
            {
                "deviceId": "device-004",
                "label": "Thermostat",
                "type": "thermostat",
                "temperature": 72,
                "mode": "auto",
            },
            {
                "deviceId": "device-005",
                "label": "Motion Sensor - Hallway",
                "type": "motionSensor",
                "motion": "inactive",
            },
        ]

    def device_list(self) -> List[Dict[str, Any]]:
        """
        List all devices.

        Returns:
            List of device objects with id, name, type, status
        """
        if self.mock_mode:
            return self.mock_devices

        # Real API call
        headers = {"Authorization": f"Bearer {self.api_token}"}
        try:
            response = requests.get(f"{self.api_url}/devices", headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            return data.get("items", [])
        except Exception as e:
            return {"error": f"Failed to list devices: {str(e)}"}

    def device_status(self, device_id: str) -> Dict[str, Any]:
        """
        Get status of a specific device.

        Args:
            device_id: Device ID

        Returns:
            Device status object
        """
        if self.mock_mode:
            for device in self.mock_devices:
                if device["deviceId"] == device_id:
                    return device
            return {"error": f"Device {device_id} not found"}

        # Real API call
        headers = {"Authorization": f"Bearer {self.api_token}"}
        try:
            response = requests.get(
                f"{self.api_url}/devices/{device_id}/status", headers=headers, timeout=10
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": f"Failed to get device status: {str(e)}"}

    def switch_on(self, device_id: str) -> Dict[str, Any]:
        """Turn on a switch device."""
        if self.mock_mode:
            for device in self.mock_devices:
                if device["deviceId"] == device_id and device["type"] == "switch":
                    device["status"] = "on"
                    return {"success": True, "device": device_id, "status": "on"}
            return {"error": f"Device {device_id} not found or not a switch"}

        return self._execute_command(device_id, "switch", "on")

    def switch_off(self, device_id: str) -> Dict[str, Any]:
        """Turn off a switch device."""
        if self.mock_mode:
            for device in self.mock_devices:
                if device["deviceId"] == device_id and device["type"] == "switch":
                    device["status"] = "off"
                    return {"success": True, "device": device_id, "status": "off"}
            return {"error": f"Device {device_id} not found or not a switch"}

        return self._execute_command(device_id, "switch", "off")

    def lock_unlock(self, device_id: str) -> Dict[str, Any]:
        """Unlock a lock device."""
        if self.mock_mode:
            for device in self.mock_devices:
                if device["deviceId"] == device_id and device["type"] == "lock":
                    device["status"] = "unlocked"
                    return {"success": True, "device": device_id, "status": "unlocked"}
            return {"error": f"Device {device_id} not found or not a lock"}

        return self._execute_command(device_id, "lock", "unlock")

    def lock_lock(self, device_id: str) -> Dict[str, Any]:
        """Lock a lock device."""
        if self.mock_mode:
            for device in self.mock_devices:
                if device["deviceId"] == device_id and device["type"] == "lock":
                    device["status"] = "locked"
                    return {"success": True, "device": device_id, "status": "locked"}
            return {"error": f"Device {device_id} not found or not a lock"}

        return self._execute_command(device_id, "lock", "lock")

    def thermostat_set_temperature(self, device_id: str, temperature: int) -> Dict[str, Any]:
        """Set thermostat temperature."""
        if self.mock_mode:
            for device in self.mock_devices:
                if device["deviceId"] == device_id and device["type"] == "thermostat":
                    device["temperature"] = temperature
                    return {"success": True, "device": device_id, "temperature": temperature}
            return {"error": f"Device {device_id} not found or not a thermostat"}

        return self._execute_command(
            device_id,
            "thermostatCoolingSetpoint",
            "setCoolingSetpoint",
            {"temperature": temperature},
        )

    def notification_send(self, message: str) -> Dict[str, Any]:
        """Send a notification."""
        if self.mock_mode:
            return {"success": True, "message": message, "sent_at": "2026-01-05T12:00:00"}

        # Real implementation would send via notification API
        return {"success": True, "message": message}

    def _execute_command(
        self, device_id: str, capability: str, command: str, args: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """Execute a device command via SmartThings API."""
        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
        }

        payload = {
            "commands": [
                {
                    "component": "main",
                    "capability": capability,
                    "command": command,
                    "arguments": args or [],
                }
            ]
        }

        try:
            response = requests.post(
                f"{self.api_url}/devices/{device_id}/commands",
                json=payload,
                headers=headers,
                timeout=10,
            )
            response.raise_for_status()
            return {"success": True, "response": response.json()}
        except Exception as e:
            return {"error": f"Command execution failed: {str(e)}"}


class FileSystemTools:
    """File system tools for evaluation (sandboxed)."""

    def __init__(self, sandbox_dir: str = "/tmp/provsafe_sandbox"):
        """
        Initialize file system tools.

        Args:
            sandbox_dir: Sandbox directory for file operations
        """
        self.sandbox_dir = sandbox_dir
        os.makedirs(sandbox_dir, exist_ok=True)

        # Create mock files for testing
        self._create_mock_files()

    def _create_mock_files(self):
        """Create mock files for evaluation."""
        mock_files = {
            "notes.txt": "Meeting notes from today...",
            "report.pdf": "[PDF binary data]",
            "config.json": '{"setting1": "value1", "setting2": "value2"}',
        }

        for filename, content in mock_files.items():
            filepath = os.path.join(self.sandbox_dir, filename)
            with open(filepath, "w") as f:
                f.write(content)

    def fs_read(self, path: str) -> str:
        """
        Read a file.

        Args:
            path: File path (relative to sandbox)

        Returns:
            File contents
        """
        full_path = os.path.join(self.sandbox_dir, path.lstrip("/"))

        # Security: Prevent path traversal
        if not os.path.abspath(full_path).startswith(os.path.abspath(self.sandbox_dir)):
            return {"error": "Path traversal detected"}

        try:
            with open(full_path, "r") as f:
                return f.read()
        except Exception as e:
            return {"error": f"Failed to read file: {str(e)}"}

    def fs_write(self, path: str, content: str) -> Dict[str, Any]:
        """
        Write to a file.

        Args:
            path: File path (relative to sandbox)
            content: Content to write

        Returns:
            Success status
        """
        full_path = os.path.join(self.sandbox_dir, path.lstrip("/"))

        # Security: Prevent path traversal
        if not os.path.abspath(full_path).startswith(os.path.abspath(self.sandbox_dir)):
            return {"error": "Path traversal detected"}

        try:
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            with open(full_path, "w") as f:
                f.write(content)
            return {"success": True, "path": path, "bytes_written": len(content)}
        except Exception as e:
            return {"error": f"Failed to write file: {str(e)}"}

    def fs_delete(self, path: str) -> Dict[str, Any]:
        """
        Delete a file.

        Args:
            path: File path (relative to sandbox)

        Returns:
            Success status
        """
        full_path = os.path.join(self.sandbox_dir, path.lstrip("/"))

        # Security: Prevent path traversal
        if not os.path.abspath(full_path).startswith(os.path.abspath(self.sandbox_dir)):
            return {"error": "Path traversal detected"}

        try:
            os.remove(full_path)
            return {"success": True, "path": path}
        except Exception as e:
            return {"error": f"Failed to delete file: {str(e)}"}

    def fs_list(self, directory: str = ".") -> List[str]:
        """
        List files in a directory.

        Args:
            directory: Directory path (relative to sandbox)

        Returns:
            List of filenames
        """
        full_path = os.path.join(self.sandbox_dir, directory.lstrip("/"))

        # Security: Prevent path traversal
        if not os.path.abspath(full_path).startswith(os.path.abspath(self.sandbox_dir)):
            return {"error": "Path traversal detected"}

        try:
            return os.listdir(full_path)
        except Exception as e:
            return {"error": f"Failed to list directory: {str(e)}"}
