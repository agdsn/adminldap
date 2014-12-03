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
    USER_BASE_DN = u'ou=people,dc=agdsn,dc=de'
    GROUP_BASE_DN = u'ou=group,dc=agdsn,dc=de'
    # DN templates for new objects
    USER_DN_TEMPLATE = u'uid=%(uid)s,ou=people,dc=agdsn,dc=de'
    GROUP_DN_TEMPLATE = u'cn=%(cn)s,ou=group,dc=agdsn,dc=de'
    # Query filters
    USER_FILTER = u'(&(objectClass=inetOrgPerson)(uid=%s))'
    USERS_FILTER = u'(objectClass=inetOrgPerson)'
    GROUP_FILTER = u'(&(objectClass=groupOfMembers)(cn=%s))'
    GROUPS_FILTER = u'(objectClass=groupOfMembers)'
    GROUPS_OF_FILTER = u'(&(objectClass=groupOfMembers)(member=%s))'
    NON_GROUPS_OF_FILTER = u'(&(objectClass=groupOfMembers)(!(|(member=%s))))'
    MEMBERS_OF_FILTER = u'(&(objectClass=inetOrgPerson)(memberOf=%s))'
    NON_MEMBERS_OF_FILTER = u'(&(objectClass=inetOrgPerson)(!(memberOf=%s)))'
