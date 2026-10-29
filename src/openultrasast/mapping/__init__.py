"""Entry-point mapping package: legacy recognisers plus the strategy registry."""

from .legacy import *  # noqa: F401,F403
from .legacy import _php_methods as _php_methods  # re-exported internal helpers (enforcement adapter)
from .legacy import _php_routes as _php_routes
