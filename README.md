AdminLDAP
=========

Simple web-interface to manage users and groups stored in an OpenLDAP server
and allow individual users to manage their details and password.

Requirements
------------
* Python 2
* Web-Server speaking WSGi
* OpenLDAP with
  - memberof overlay
  - refint overlay
  - [RFC2307bis](http://tools.ietf.org/html/draft-howard-rfc2307bis-02) instead of NIS schema
  
Setup
-----
1. Install OpenLDAP
2. Replace the default nis schema that ships with OpenLDAP with the included rfc2307bis schema
3. Enable and configure the memberof and refint overlays (see the included sample slapd.conf)
4. Setup an appropriate access control list; adminldap uses a two-phase bind process.
   Users must login through HTTP Authentication.
   First it binds using BIND_DN and BIND_PW (anonymous bind by default) to find the dn for
   the uid the user provided through HTTP Basic Auth, then it binds with the actual user. 
5. Set options in app.cfg
