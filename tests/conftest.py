import os
import sys

import pytest

# so both test modules can import the shared analysis_helpers module beside them
sys.path.insert(0, os.path.dirname(__file__))


@pytest.fixture(scope='session', autouse=True)
def set_terminal_properties():
    """Make sure terminal width is set to 120 columns and color is disabled for
    consistent test output."""
    os.environ['COLUMNS'] = '120'
    os.environ['NO_COLOR'] = '1'
    # any FORCE_COLOR, even '0', makes Rich style a piped stdout
    os.environ.pop('FORCE_COLOR', None)
