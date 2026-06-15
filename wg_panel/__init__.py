from .core import app

# Import side-effect modules so middleware and routes are registered on app import.
from . import middleware, routes  # noqa: F401,E402

__all__ = ["app"]
