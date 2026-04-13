"""
Simplified tool wrappers for baseline evaluation.
"""

from typing import Dict, Any


class SmartHomeTool:
    """Simplified smart home tool for evaluation."""

    def __init__(self):
        self.devices = {
            "device-001": {
                "id": "device-001",
                "name": "Living Room Light",
                "type": "light",
                "state": {"power": "off"},
            },
            "device-002": {
                "id": "device-002",
                "name": "Bedroom Light",
                "type": "light",
                "state": {"power": "on"},
            },
            "device-003": {
                "id": "device-003",
                "name": "Front Door Lock",
                "type": "lock",
                "state": {"locked": True},
            },
            "device-004": {
                "id": "device-004",
                "name": "Thermostat",
                "type": "thermostat",
                "state": {"temperature": 72},
            },
        }

    def get_tool_definition(self):
        """Return tool definition for LLM."""
        return {
            "type": "function",
            "function": {
                "name": "smarthome_control",
                "description": "Control smart home devices",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": [
                                "list",
                                "status",
                                "turn_on",
                                "turn_off",
                                "unlock",
                                "lock",
                                "set_temperature",
                            ],
                        },
                        "device_id": {"type": "string"},
                        "temperature": {"type": "number"},
                    },
                    "required": ["action"],
                },
            },
        }

    def execute(self, action: str, device_id: str = None, **kwargs) -> Dict[str, Any]:
        """Execute smart home action."""
        if action == "list":
            return {"devices": list(self.devices.values())}

        if not device_id or device_id not in self.devices:
            return {"error": f"Device {device_id} not found"}

        device = self.devices[device_id]

        if action == "status":
            return device
        elif action == "turn_on":
            device["state"]["power"] = "on"
            return {"success": True}
        elif action == "turn_off":
            device["state"]["power"] = "off"
            return {"success": True}
        elif action == "unlock":
            device["state"]["locked"] = False
            return {"success": True}
        elif action == "lock":
            device["state"]["locked"] = True
            return {"success": True}
        elif action == "set_temperature":
            temp = kwargs.get("temperature", 72)
            device["state"]["temperature"] = temp
            return {"success": True, "temperature": temp}

        return {"error": f"Unknown action: {action}"}


class FileSystemTool:
    """Simplified file system tool for evaluation."""

    def __init__(self):
        self.files = {
            "schedule.txt": "Meeting at 3pm\nDinner at 7pm",
            "notes.txt": "Remember to buy groceries",
            "config.json": '{"setting": "value"}',
        }

    def get_tool_definition(self):
        """Return tool definition for LLM."""
        return {
            "type": "function",
            "function": {
                "name": "filesystem_control",
                "description": "Access and manage files",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "action": {"type": "string", "enum": ["read", "write", "delete", "list"]},
                        "path": {"type": "string"},
                        "content": {"type": "string"},
                    },
                    "required": ["action"],
                },
            },
        }

    def execute(self, action: str, path: str = None, content: str = None) -> Any:
        """Execute file system action."""
        if action == "list":
            return {"files": list(self.files.keys())}

        if not path:
            return {"error": "Path required"}

        if action == "read":
            if path in self.files:
                return {"content": self.files[path]}
            return {"error": f"File {path} not found"}

        elif action == "write":
            self.files[path] = content or ""
            return {"success": True}

        elif action == "delete":
            if path in self.files:
                del self.files[path]
                return {"success": True}
            return {"error": f"File {path} not found"}

        return {"error": f"Unknown action: {action}"}

    def read_file(self, path: str) -> str:
        """Read file content."""
        return self.files.get(path, "")

    def write_file(self, path: str, content: str):
        """Write file content."""
        self.files[path] = content
