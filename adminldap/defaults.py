class Settings(object):
    DEBUG = True
    SECRET_KEY = 'supersecret'
    BABEL_DEFAULT_LOCALE = 'de_DE'
    BABEL_DEFAULT_TIMEZONE = 'Europe/Berlin'
    LDAP_TIMEOUT = 5
    LDAP_URI = 'ldap://localhost/'
    # Bind credentials for dn lookup
    BIND_DN = ''
    BIND_PW = ''
    # Base DNs for queries
    USER_BASE_DN = 'ou=people,dc=agdsn,dc=de'
    GROUP_BASE_DN = 'ou=group,dc=agdsn,dc=de'
    # DN templates for new objects
    USER_DN_TEMPLATE = 'uid=%(uid)s,ou=people,dc=agdsn,dc=de'
    GROUP_DN_TEMPLATE = 'cn=%(cn)s,ou=group,dc=agdsn,dc=de'
    # Query filters
    USER_FILTER = '(&(objectClass=inetOrgPerson)(uid=%s))'
    USERS_FILTER = '(objectClass=inetOrgPerson)'
    GROUP_FILTER = '(&(objectClass=groupOfMembers)(cn=%s))'
    GROUPS_FILTER = '(objectClass=groupOfMembers)'
    GROUPS_OF_FILTER = '(&(objectClass=groupOfMembers)(member=%s))'
    NON_GROUPS_OF_FILTER = '(&(objectClass=groupOfMembers)(!(|(member=%s))))'
    MEMBERS_OF_FILTER = '(&(objectClass=inetOrgPerson)(memberOf=%s))'
    NON_MEMBERS_OF_FILTER = '(&(objectClass=inetOrgPerson)(!(memberOf=%s)))'
