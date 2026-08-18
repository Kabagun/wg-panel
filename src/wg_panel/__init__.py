from importlib import import_module

from .core import app

# Register middleware and routes after the shared Flask app exists.
import_module(".middleware", __name__)
import_module(".routes", __name__)

__all__ = ["app"]
