"""Legacy Python Research backend for threat analysis."""

# Import submodules to make them available as attributes
from . import analyzers
from . import api
from . import core
from . import heuristics
from . import utils
from . import persistence
from . import engine

__all__ = [
    'analyzers',
    'api',
    'core',
    'heuristics',
    'utils',
    'persistence',
    'engine',
]

