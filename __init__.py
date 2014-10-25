# coding=utf8
import collections
from datetime import datetime
from itertools import chain, imap
from operator import methodcaller
import re
from flask import Flask, redirect, render_template, request, url_for, jsonify
from flask.ext.wtf import Form
from flask.ext.babel import Babel
import ldap
from ldap.filter import filter_format
import ldap.modlist
import ldap.resiter
import ldappool
import passlib.hash
import wrapt
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Email, EqualTo, Regexp

app = Flask('adminldap')
app.config.from_pyfile('app.cfg')
babel = Babel()
babel.init_app(app)

USER_DISPLAY_ATTRIBUTES = ['uid', 'givenName', 'sn', 'mail', 'createTimestamp', 'modifyTimestamp']
GROUP_DISPLAY_ATTRIBUTES = ['cn', 'createTimestamp', 'modifyTimestamp']
LDAP_TIME_FORMAT = '%Y%m%d%H%M%SZ'


User = collections.namedtuple('User',
                              ('dn', 'uid', 'givenName', 'sn', 'userPassword',
                               'mail', 'createTimestamp', 'modifyTimestamp'))

Group = collections.namedtuple('Group',
                               ('dn', 'cn', 'createTimestamp',
                                'modifyTimestamp'))


class Blub(ldappool.StateConnector, ldap.resiter.ResultProcessor):
    pass

pool = ldappool.ConnectionManager(app.config['LDAP_URI'], connector_cls=Blub)


class LDAPError(Exception):
    def __init__(self, msg, code=503):
        super(LDAPError, self).__init__(msg)
        self.code = code


class NoResults(Exception):
    pass


class MultipleResults(Exception):
    pass


@app.errorhandler(LDAPError)
def handle_ldap_error(e):
    """:param LDAPError e: """
    return render_template('error.html', error=e.message), e.code


@app.errorhandler(ldappool.BackendError)
def handle_backend_error(e):
    return render_template('error.html', error=u"Backend-Fehler ({0})".format(e.message)), 503


@app.errorhandler(ldap.INVALID_CREDENTIALS)
def handle_invalid_credentials(e):
    return render_template('error.html', error=u"Falsche Zugangsdaten."), 503


@app.errorhandler(NoResults)
def handle_no_results(e):
    return render_template('error.html', error=u"Objekt nicht gefunden"), 404


@wrapt.decorator
def with_connection(wrapped, instance, args, kwargs):
    bind_dn = app.config['BIND_DN']
    bind_pw = app.config['BIND_PW']
    with pool.connection(bind_dn, bind_pw) as connection:
        kwargs['connection'] = connection
        return wrapped(*args, **kwargs)


@app.route('/')
@app.route('/me')
def index():
    return render_template('me.html')


class LoginForm(Form):
    name = StringField(validators=[DataRequired()])
    password = PasswordField(validators=[DataRequired()])


@app.route('/login')
def login():
    form = LoginForm()
    return render_template('login.html', form=form)


def to_entries(result):
    res_type, res_data, res_msg_id, res_controls = result
    return res_data


def to_user(res_data):
    dn, entry = res_data
    created_at = datetime.strptime(entry['createTimestamp'][0],
                                   LDAP_TIME_FORMAT)
    modified_at = datetime.strptime(entry['modifyTimestamp'][0],
                                    LDAP_TIME_FORMAT)
    return User(dn, entry['uid'][0], entry['givenName'][0], entry['sn'][0],
                None, entry['mail'][0], created_at, modified_at)


def to_group(res_data):
    dn, entry = res_data
    created_at = datetime.strptime(entry['createTimestamp'][0],
                                   LDAP_TIME_FORMAT)
    modified_at = datetime.strptime(entry['modifyTimestamp'][0],
                                    LDAP_TIME_FORMAT)
    return Group(dn, entry['cn'][0], created_at, modified_at)


def get_single_object(connection, filter_string, base, attributes, creator):
    timeout = app.config['LDAP_TIMEOUT']
    try:
        entries = connection.search_st(base, ldap.SCOPE_SUBTREE, filter_string,
                                       attributes, timeout=timeout)
    except ldap.NO_SUCH_OBJECT:
        raise LDAPError(u"Fehler in LDAP-Struktur: "
                        u"Benötigtes Objekt {0} fehlt".format(base))
    if not entries:
        raise NoResults()
    if len(entries) > 1:
        raise MultipleResults()
    return creator(entries[0])


def get_objects(connection, filter_string, base, attributes, creator):
    try:
        msg_id = connection.search(base, ldap.SCOPE_SUBTREE, filter_string,
                                   attributes)
    except ldap.NO_SUCH_OBJECT:
        raise LDAPError(u"Fehler in LDAP-Struktur: "
                        u"Benötigtes Objekt {0} fehlt".format(base))
    timeout = app.config['LDAP_TIMEOUT']
    results = imap(to_entries, connection.allresults(msg_id, timeout))
    group_entries = chain(*results)
    return imap(creator, group_entries)


def get_user(connection, uid):
    user_filter = filter_format(app.config['USER_FILTER'], (uid,))
    return get_single_object(connection, user_filter, app.config['USER_DN'],
                             USER_DISPLAY_ATTRIBUTES, to_user)


def get_users(connection):
    return get_objects(connection, app.config['USERS_FILTER'],
                       app.config['USER_DN'], USER_DISPLAY_ATTRIBUTES, to_user)


def get_members(connection):
    return get_objects(connection, app.config['MEMBERSOF_FILTER'],
                       app.config['USER_DN'], USER_DISPLAY_ATTRIBUTES, to_user)


def get_group(connection, cn):
    filter_string = filter_format(app.config['GROUP_FILTER'], (cn,))
    return get_single_object(connection, filter_string, app.config['GROUP_DN'],
                             GROUP_DISPLAY_ATTRIBUTES, to_group)


def get_groups_of(connection, uid):
    filter_string = filter_format(app.config['GROUPS_OF_FILTER'], (uid,))
    return get_objects(connection, filter_string, app.config['GROUP_DN'],
                       GROUP_DISPLAY_ATTRIBUTES, to_group)


def get_groups(connection):
    return get_objects(connection, app.config['GROUPS_FILTER'],
                       app.config['GROUP_DN'], GROUP_DISPLAY_ATTRIBUTES,
                       to_group)


def request_wants_json():
    best = request.accept_mimetypes \
        .best_match(['application/json', 'text/html'])
    return best == 'application/json' and \
        request.accept_mimetypes[best] > \
        request.accept_mimetypes['text/html']


@app.route('/users/<string:uid>')
@app.route('/users/<string:uid>/view')
@with_connection
def view_user(uid, connection):
    user = get_user(connection, uid)
    groups = get_groups_of(connection, uid)
    return render_template('user_view.html', user=user, groups=groups)


@app.route('/users/<string:uid>/edit')
@with_connection
def edit_user(uid, connection):
    return redirect(url_for())


@app.route('/users/<string:uid>/delete')
@with_connection
def delete_user(uid, connection):
    user = get_user(connection, uid)
    connection.delete_s(user.dn)
    return redirect(url_for())


@app.route('/groups/<string:cn>/edit')
@with_connection
def edit_group(cn, connection):
    return redirect(url_for())


@app.route('/groups/<string:cn>/delete')
@with_connection
def delete_group(cn, connection):
    group = get_group(connection, cn)
    connection.delete_s(group.dn)
    return redirect(url_for())


def user_to_json(user):
    user_dict = user._asdict()
    user_dict.update(
        viewUrl=url_for('.view_user', uid=user.uid),
        editUrl=url_for('.edit_user', uid=user.uid),
        deleteUrl=url_for('.delete_user', uid=user.uid),
    )
    return user_dict


def groups_to_json(group):
    user_dict = group._asdict()
    user_dict.update(
        viewUrl=url_for('.view_group', cn=group.cn),
        editUrl=url_for('.edit_group', cn=group.cn),
        deleteUrl=url_for('.delete_group', cn=group.cn),
    )
    return user_dict


@app.route('/users/')
@with_connection
def view_users(connection):
    if request_wants_json():
        users = get_users(connection)
        return jsonify(users=map(user_to_json, users))
    return render_template('users.html')


@app.route('/groups/', methods=['GET', 'POST'])
@with_connection
def view_groups(connection):
    if request_wants_json():
        groups = get_groups(connection)
        return jsonify(groups=map(groups_to_json, groups))
    return render_template('groups.html')


@app.route('/groups/<string:cn>')
@with_connection
def view_group(cn, connection):
    group = get_group(connection, cn)
    return render_template('group_view.html', group=group)


class UserForm(Form):
    uid = StringField(u"Login", validators=[DataRequired()])
    givenName = StringField(u"Vorname", validators=[DataRequired()])
    sn = StringField(u"Nachname", validators=[DataRequired()])
    userPassword = PasswordField(u"Passwort", validators=[DataRequired()])
    userPassword_confirmation = PasswordField(
        u"Passwort bestätigen",
        validators=[DataRequired(), EqualTo("userPassword")])
    mail = StringField(u"E-Mail", validators=[Email()])


def encrypt_password(password):
    return passlib.hash.ldap_sha512_crypt.encrypt(password)


@app.route('/users/create', methods=['GET', 'POST'])
@with_connection
def create_user(connection=None):
    form = UserForm()
    if form.validate_on_submit():
        uid = form.uid.data.encode('utf8')
        dn = "uid={1},{0}".format(app.config['USER_DN'], uid)
        cn = '{0} {1}'.format(form.givenName.data.encode('utf8'),
                              form.sn.data.encode('utf8'))
        password = encrypt_password(form.userPassword.data.encode('utf8'))
        entry = {
            'objectClass': ['inetOrgPerson'],
            'uid': uid,
            'sn': form.sn.data.encode('utf8'),
            'givenName': form.givenName.data.encode('utf8'),
            'cn': cn,
            'userPassword': password,
            'mail': form.mail.data.encode('utf8'),
        }
        try:
            connection.add_s(dn, ldap.modlist.addModlist(entry))
        except ldap.ALREADY_EXISTS:
            raise LDAPError(u'Benutzer mit Login "{0}" '
                            u'bereits vorhanden.'.format(uid))
        return redirect(url_for('.view_user', uid=form.uid.data))
    return render_template('user_create.html', form=form)


class GroupForm(Form):
    cn = StringField(u"Name",
                     validators=[DataRequired(), Regexp(r'\w+', re.UNICODE)])


@app.route('/groups/create', methods=['GET', 'POST'])
@with_connection
def create_group(connection):
    form = GroupForm()
    if form.validate_on_submit():
        cn = form.cn.data.encode('utf8')
        dn = "cn={1},{0}".format(app.config['GROUP_DN'], cn)
        entry = {
            'objectClass': ['groupOfMembers'],
            'cn': cn,
        }
        try:
            connection.add_s(dn, ldap.modlist.addModlist(entry))
        except ldap.ALREADY_EXISTS:
            raise LDAPError(u'Gruppe mit Name "{0}" '
                            u'bereits vorhanden.'.format(cn))
        return redirect(url_for('.view_group', cn=cn))
    return render_template('group_create.html', form=form)


if __name__ == '__main__':
    app.run(debug=True)