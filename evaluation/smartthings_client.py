#!/usr/bin/env python3
"""
SmartThings API Client

Provides real smart home device integration for PROVSAFE evaluation.
"""

import logging
import time
from typing import Any, Dict, List, Optional

import requests

from config import SMARTTHINGS_API_URL, SMARTTHINGS_TOKEN


class SmartThingsClient:
    """Client for interacting with SmartThings API."""
    
    def __init__(self, token: str = SMARTTHINGS_TOKEN):
        self.token = token
        self.base_url = SMARTTHINGS_API_URL
        self.logger = logging.getLogger("SmartThings")
        
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }
        
        # Cache for device list
        self._device_cache: Optional[List[Dict]] = None
        self._cache_time: float = 0
        self._cache_ttl: float = 60.0  # 1 minute
    
    def _request(self, method: str, endpoint: str, **kwargs) -> Dict:
        """Make authenticated request to SmartThings API."""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        
        try:
            response = requests.request(
                method,
                url,
                headers=self.headers,
                timeout=10,
                **kwargs
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self.logger.error(f"SmartThings API error: {e}")
            raise
    
    def list_devices(self) -> List[Dict[str, Any]]:
        """
        List all devices in the SmartThings account.
        
        Returns:
            List of device dictionaries with id, name, label, capabilities
        """
        now = time.time()
        if self._device_cache and (now - self._cache_time) < self._cache_ttl:
            return self._device_cache
        
        try:
            response = self._request("GET", "/devices")
            devices = response.get("items", [])
            
            # Simplify device info
            device_list = []
            for device in devices:
                device_list.append({
                    "id": device.get("deviceId"),
                    "name": device.get("name", "Unknown"),
                    "label": device.get("label", device.get("name", "Unknown")),
                    "type": device.get("type", "UNKNOWN"),
                    "capabilities": [c.get("id") for c in device.get("components", [{}])[0].get("capabilities", [])],
                })
            
            self._device_cache = device_list
            self._cache_time = now
            
            self.logger.info(f"Found {len(device_list)} SmartThings devices")
            return device_list
            
        except Exception as e:
            self.logger.error(f"Failed to list devices: {e}")
            return []
    
    def get_device_status(self, device_id: str) -> Dict[str, Any]:
        """
        Get current status of a device.
        
        Args:
            device_id: SmartThings device ID
            
        Returns:
            Dictionary with device status (switch, level, temperature, etc.)
        """
        try:
            response = self._request("GET", f"/devices/{device_id}/status")
            
            # Extract main component status
            components = response.get("components", {})
            main_component = components.get("main", {})
            
            status = {}
            for capability, data in main_component.items():
                if isinstance(data, dict):
                    for attr, value_obj in data.items():
                        if isinstance(value_obj, dict) and "value" in value_obj:
                            status[f"{capability}.{attr}"] = value_obj["value"]
            
            return status
            
        except Exception as e:
            self.logger.error(f"Failed to get device status for {device_id}: {e}")
            return {}
    
    def execute_command(
        self,
        device_id: str,
        capability: str,
        command: str,
        arguments: Optional[List[Any]] = None
    ) -> bool:
        """
        Execute a command on a device.
        
        Args:
            device_id: SmartThings device ID
            capability: Capability name (e.g., "switch")
            command: Command name (e.g., "on", "off", "setLevel")
            arguments: Optional command arguments
            
        Returns:
            True if successful, False otherwise
        """
        try:
            payload = {
                "commands": [
                    {
                        "component": "main",
                        "capability": capability,
                        "command": command,
                        "arguments": arguments or []
                    }
                ]
            }
            
            self._request("POST", f"/devices/{device_id}/commands", json=payload)
            self.logger.info(f"Executed: {capability}.{command} on {device_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to execute command: {e}")
            return False
    
    def list_locations(self) -> List[Dict[str, Any]]:
        """List all SmartThings locations."""
        try:
            response = self._request("GET", "/locations")
            return response.get("items", [])
        except Exception as e:
            self.logger.error(f"Failed to list locations: {e}")
            return []
    
    def get_location_devices(self, location_id: str) -> List[Dict[str, Any]]:
        """Get all devices in a specific location."""
        try:
            devices = self.list_devices()
            return [d for d in devices if d.get("locationId") == location_id]
        except Exception as e:
            self.logger.error(f"Failed to get location devices: {e}")
            return []
    
    def health_check(self) -> bool:
        """Check if SmartThings API is accessible."""
        try:
            devices = self.list_devices()
            self.logger.info(f"SmartThings health check: OK ({len(devices)} devices)")
            return True
        except Exception as e:
            self.logger.error(f"SmartThings health check failed: {e}")
            return False
