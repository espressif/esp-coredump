import os

import pytest


@pytest.fixture(scope='session', autouse=True)
def set_terminal_properties():
    """Make sure terminal width is set to 120 columns and color is disabled for
    consistent test output."""
    os.environ['COLUMNS'] = '120'
    os.environ['NO_COLOR'] = '1'
