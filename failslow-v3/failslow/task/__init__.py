"""
Task module - top-level interface for external clients.
"""
from .task import ITask, Task
from .task_factory import TaskFactory

__all__ = ["ITask", "Task", "TaskFactory"]
