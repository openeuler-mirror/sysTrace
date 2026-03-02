"""Task factory for creating and managing Task instances."""
from typing import Dict, Optional

from .task import Task


class TaskFactory:
    """Factory for creating and accessing Task instances."""

    _tasks: Dict[str, Task] = {}

    @classmethod
    def register(cls, task_name: str, task: Task) -> None:
        """Register a task instance."""
        cls._tasks[task_name] = task

    @classmethod
    def get(cls, task_name: str) -> Optional[Task]:
        """Get a registered task by name."""
        return cls._tasks.get(task_name)

    @classmethod
    def create(cls, config_path: str) -> Task:
        """Create and register a new Task from config file."""
        task = Task(config_path=config_path)
        cls.register(task._task_name, task)
        return task

    @classmethod
    def clear(cls) -> None:
        """Clear all registered tasks. Useful for testing."""
        cls._tasks.clear()
