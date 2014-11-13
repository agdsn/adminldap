from __future__ import absolute_import

activate_this = '/path/to/env/bin/activate_this.py'
execfile(activate_this, dict(__file__=activate_this))

from . import app as application
