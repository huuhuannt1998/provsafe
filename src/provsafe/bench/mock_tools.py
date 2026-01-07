"""Mock tools for testing with deterministic behavior."""

import random
from typing import Dict, Any, List, Optional
from datetime import datetime


class MockTool:
    """Base class for mock tools."""
    
    def __init__(self, seed: Optional[int] = None):
        self.seed = seed
        self._rng = random.Random(seed)
    
    def execute(self, action: str, resource: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool action."""
        raise NotImplementedError


class MockFileSystem(MockTool):
    """Mock file system tool."""
    
    def __init__(self, seed: Optional[int] = None):
        super().__init__(seed)
        self._filesystem: Dict[str, str] = {
            "/home/user/documents/notes.txt": "Meeting notes from last week",
            "/home/user/documents/report.pdf": "[Binary PDF content]",
            "/home/user/config.json": '{"setting": "value"}',
        }
    
    def execute(self, action: str, resource: str, args: Dict[str, Any]) -> Dict[str, Any]:
        if action == "read":
            content = self._filesystem.get(resource, None)
            if content is None:
                return {"success": False, "error": "File not found"}
            return {"success": True, "content": content}
        
        elif action == "write":
            content = args.get("content", "")
            self._filesystem[resource] = content
            return {"success": True, "bytes_written": len(content)}
        
        elif action == "delete":
            if resource in self._filesystem:
                del self._filesystem[resource]
                return {"success": True}
            return {"success": False, "error": "File not found"}
        
        elif action == "list":
            prefix = resource.rstrip("*")
            matches = [path for path in self._filesystem.keys() if path.startswith(prefix)]
            return {"success": True, "files": matches}
        
        return {"success": False, "error": f"Unknown action: {action}"}


class MockCalendar(MockTool):
    """Mock calendar tool."""
    
    def __init__(self, seed: Optional[int] = None):
        super().__init__(seed)
        self._events: List[Dict[str, Any]] = [
            {
                "id": "evt1",
                "title": "Team Meeting",
                "start": "2026-01-05T10:00:00",
                "end": "2026-01-05T11:00:00",
                "attendees": ["alice@example.com", "bob@example.com"]
            },
            {
                "id": "evt2",
                "title": "Dentist Appointment",
                "start": "2026-01-06T14:00:00",
                "end": "2026-01-06T15:00:00",
                "attendees": []
            }
        ]
    
    def execute(self, action: str, resource: str, args: Dict[str, Any]) -> Dict[str, Any]:
        if action == "read":
            event = next((e for e in self._events if e["id"] == resource), None)
            if event:
                return {"success": True, "event": event}
            return {"success": False, "error": "Event not found"}
        
        elif action == "create":
            event = {
                "id": f"evt{len(self._events) + 1}",
                "title": args.get("title", "New Event"),
                "start": args.get("start"),
                "end": args.get("end"),
                "attendees": args.get("attendees", [])
            }
            self._events.append(event)
            return {"success": True, "event_id": event["id"]}
        
        elif action == "list":
            return {"success": True, "events": self._events}
        
        elif action == "delete":
            event = next((e for e in self._events if e["id"] == resource), None)
            if event:
                self._events.remove(event)
                return {"success": True}
            return {"success": False, "error": "Event not found"}
        
        return {"success": False, "error": f"Unknown action: {action}"}


class MockNotification(MockTool):
    """Mock notification tool."""
    
    def __init__(self, seed: Optional[int] = None):
        super().__init__(seed)
        self._sent_notifications: List[Dict[str, Any]] = []
    
    def execute(self, action: str, resource: str, args: Dict[str, Any]) -> Dict[str, Any]:
        if action == "send":
            notification = {
                "recipient": resource,
                "message": args.get("message", ""),
                "timestamp": datetime.now().isoformat(),
                "id": f"notif{len(self._sent_notifications) + 1}"
            }
            self._sent_notifications.append(notification)
            return {"success": True, "notification_id": notification["id"]}
        
        elif action == "list":
            return {"success": True, "notifications": self._sent_notifications}
        
        return {"success": False, "error": f"Unknown action: {action}"}


class MockEmail(MockTool):
    """Mock email tool."""
    
    def __init__(self, seed: Optional[int] = None):
        super().__init__(seed)
        self._sent_emails: List[Dict[str, Any]] = []
    
    def execute(self, action: str, resource: str, args: Dict[str, Any]) -> Dict[str, Any]:
        if action == "send":
            email = {
                "to": resource,
                "subject": args.get("subject", ""),
                "body": args.get("body", ""),
                "timestamp": datetime.now().isoformat(),
                "id": f"email{len(self._sent_emails) + 1}"
            }
            self._sent_emails.append(email)
            return {"success": True, "email_id": email["id"]}
        
        elif action == "list":
            return {"success": True, "emails": self._sent_emails}
        
        return {"success": False, "error": f"Unknown action: {action}"}


class MockToolRegistry:
    """Registry of mock tools for testing."""
    
    def __init__(self, seed: Optional[int] = None):
        self.seed = seed
        self._tools: Dict[str, MockTool] = {
            "file_system": MockFileSystem(seed),
            "calendar": MockCalendar(seed),
            "notification": MockNotification(seed),
            "email": MockEmail(seed),
        }
    
    def execute(self, tool: str, action: str, resource: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool action."""
        mock_tool = self._tools.get(tool)
        if not mock_tool:
            return {"success": False, "error": f"Unknown tool: {tool}"}
        
        return mock_tool.execute(action, resource, args)
    
    def reset(self):
        """Reset all tools to initial state."""
        self._tools = {
            "file_system": MockFileSystem(self.seed),
            "calendar": MockCalendar(self.seed),
            "notification": MockNotification(self.seed),
            "email": MockEmail(self.seed),
        }
