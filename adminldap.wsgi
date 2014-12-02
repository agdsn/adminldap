# Set appropriate path to your virtualenv here
activate_this = '/path/to/env/bin/activate_this.py'
execfile(activate_this, dict(__file__=activate_this))

from adminldap import app as application
