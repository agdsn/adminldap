# coding=utf8
import collections
from datetime import datetime
from itertools import chain, imap
import re
import operator

from flask import (
    Flask, abort, redirect, render_template, request, url_for, jsonify,
    make_response)
from flask_login import current_user, login_required, LoginManager, UserMixin
from flask_babel import format_datetime
from flask_wtf import Form
from flask_wtf.html5 import EmailField, TelField
from flask.ext.babel import Babel
import ldap
from ldap.dn import escape_dn_chars
from ldap.filter import filter_format
import ldap.modlist
import ldap.resiter
import ldappool
import passlib.hash
from werkzeug.datastructures import WWWAuthenticate
import wrapt
from wtforms import PasswordField, SelectMultipleField, StringField
from wtforms.validators import DataRequired, Email, EqualTo, Regexp, Length


app = Flask('adminldap')
app.config.from_pyfile('app.cfg')
login_manager = LoginManager()
login_manager.init_app(app)
babel = Babel()
babel.init_app(app)
app.jinja_env.globals['OrderedDict'] = collections.OrderedDict

USER_DISPLAY_ATTRIBUTES = ['uid', 'givenName', 'sn', 'mail', 'mobile',
                           'createTimestamp', 'modifyTimestamp']
GROUP_DISPLAY_ATTRIBUTES = ['cn', 'createTimestamp', 'modifyTimestamp']
LDAP_TIME_FORMAT = '%Y%m%d%H%M%SZ'


User = collections.namedtuple('User', (
    'dn', 'uid', 'givenName', 'sn', 'userPassword', 'mail', 'mobile',
    'createTimestamp', 'modifyTimestamp'))

Group = collections.namedtuple('Group', (
    'dn', 'cn', 'createTimestamp', 'modifyTimestamp'))


class Connector(ldappool.StateConnector, ldap.resiter.ResultProcessor):
    def __init__(self, *args, **kwargs):
        ldappool.StateConnector.__init__(self, *args, **kwargs)
        self.set_option(ldap.OPT_PROTOCOL_VERSION, ldap.VERSION3)
        self.set_option(ldap.OPT_DEREF, ldap.DEREF_ALWAYS)

pool = ldappool.ConnectionManager(app.config['LDAP_URI'],
                                  connector_cls=Connector)


class AppUser(User, UserMixin):
    pass


@login_manager.request_loader
def load_user(req):
    auth = req.authorization
    if not auth:
        return None
    uid = escape_dn_chars(auth.username)
    bind_dn = app.config['BIND_DN']
    bind_pw = app.config['BIND_PW']
    with pool.connection(bind_dn, bind_pw) as conn:
        user = get_user(conn, uid)

    try:
        with pool.connection(user.dn, auth.password) as conn:
            return AppUser(*get_user(conn, auth.username))
    except ldap.INVALID_CREDENTIALS:
        return None


@login_manager.unauthorized_handler
def handle_unauthorized():
    authenticate = WWWAuthenticate()
    authenticate.set_basic('AdminLDAP Login')
    response = make_response(error_response(
        u'Authentifizierung erforderlich',401))
    response.headers['WWW-Authenticate'] = authenticate.to_header()
    return response


class LDAPError(Exception):
    def __init__(self, msg, code=503):
        super(LDAPError, self).__init__(msg)
        self.code = code


class NoResults(Exception):
    def __init__(self, filter_string):
        self.filter_string = filter_string


class MultipleResults(Exception):
    pass


def error_response(message, code):
    if request_wants_json():
        return jsonify(error=message), code
    return render_template('error.html', error=message), code


@app.errorhandler(LDAPError)
def handle_ldap_error(e):
    """:param LDAPError e: """
    return error_response(e.message, e.code)


@app.errorhandler(ldappool.BackendError)
def handle_backend_error(e):
    return error_response(u"Backend-Fehler ({0})".format(e.message), 503)


@app.errorhandler(ldap.INVALID_CREDENTIALS)
def handle_invalid_credentials(e):
    return error_response(u"Falsche Zugangsdaten.", 503)


@app.errorhandler(NoResults)
def handle_no_results(e):
    return error_response(
        u"Kein Objekt mittels {0} gefunden.".format(e.filter_string), 404)


@wrapt.decorator
def with_connection(wrapped, instance, args, kwargs):
    bind_dn = app.config['BIND_DN']
    bind_pw = app.config['BIND_PW']
    with pool.connection(bind_dn, bind_pw) as connection:
        kwargs['connection'] = connection
        return wrapped(*args, **kwargs)


class PasswordForm(Form):
    userPassword = PasswordField(u"Passwort",
                                 validators=[DataRequired(), Length(min=8)])
    userPassword_confirm = PasswordField(u"Passwort bestätigen",
                                         validators=[EqualTo("userPassword")])


class DetailsForm(Form):
    givenName = StringField(u"Vorname")
    sn = StringField(u"Nachname")
    mail = EmailField(u"E-Mail")
    mobile = TelField(u"Handy")


@app.route('/')
@app.route('/self', methods=['GET', 'POST'])
@login_required
@with_connection
def manage_self(connection):
    action = request.args.get('action')
    if action == 'update-password':
        return update_password(connection)
    if action == 'update-details':
        return update_details(connection)
    password_form = PasswordForm()
    details_form = DetailsForm(obj=current_user)
    return render_template('self.html', user=current_user,
                           password_form=password_form,
                           details_form=details_form)


def update_password(connection):
    password_form = PasswordForm()
    details_form = DetailsForm(formdata=None, obj=current_user)
    if password_form.validate_on_submit():
        password = encrypt_password(password_form.userPassword.data).encode('utf8')
        mod_list = [(ldap.MOD_REPLACE, 'userPassword', password)]
        connection.modify_s(current_user.dn, mod_list)
        return redirect(url_for('.manage_self'))
    return render_template('self.html', user=current_user,
                           password_form=password_form,
                           details_form=details_form)


def update_details(connection):
    password_form = PasswordForm(formdata=None)
    details_form = DetailsForm(obj=current_user)
    if details_form.validate_on_submit():
        mod_list = [(ldap.MOD_REPLACE, attribute, value.encode('utf8'))
                    for attribute, value in details_form.data.iteritems()
                    if value]
        connection.modify_s(current_user.dn, mod_list)
    return render_template('self.html', user=current_user,
                           password_form=password_form,
                           details_form=details_form)


def get_or_none(entry, attribute):
    values = entry.get(attribute)
    return values and values[0]


def to_entries(result):
    res_type, res_data, res_msg_id, res_controls = result
    return res_data


def to_user(res_data):
    dn, entry = res_data
    created_at = datetime.strptime(entry['createTimestamp'][0],
                                   LDAP_TIME_FORMAT)
    modified_at = datetime.strptime(entry['modifyTimestamp'][0],
                                    LDAP_TIME_FORMAT)
    return User(dn, entry['uid'][0], get_or_none(entry, 'givenName'),
                get_or_none(entry, 'sn'), None, get_or_none(entry, 'mail'),
                get_or_none(entry, 'mobile'), created_at, modified_at)


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
        raise NoResults(filter_string)
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
    return get_single_object(connection, user_filter,
                             app.config['USER_BASE_DN'],
                             USER_DISPLAY_ATTRIBUTES, to_user)


def get_users(connection):
    return get_objects(connection, app.config['USERS_FILTER'],
                       app.config['USER_BASE_DN'], USER_DISPLAY_ATTRIBUTES,
                       to_user)


def get_members(connection, group):
    filter_string = filter_format(app.config['MEMBERS_OF_FILTER'], (group.dn,))
    return get_objects(connection, filter_string,
                       app.config['USER_BASE_DN'], USER_DISPLAY_ATTRIBUTES,
                       to_user)


def get_non_members(connection, group):
    filter_string = filter_format(app.config['NON_MEMBERS_OF_FILTER'],
                                  (group.dn,))
    return get_objects(connection, filter_string,
                       app.config['USER_BASE_DN'], USER_DISPLAY_ATTRIBUTES,
                       to_user)


def get_group(connection, cn):
    filter_string = filter_format(app.config['GROUP_FILTER'], (cn,))
    return get_single_object(connection, filter_string,
                             app.config['GROUP_BASE_DN'],
                             GROUP_DISPLAY_ATTRIBUTES, to_group)


def get_groups_of(connection, user):
    filter_string = filter_format(app.config['GROUPS_OF_FILTER'], (user.dn,))
    return get_objects(connection, filter_string, app.config['GROUP_BASE_DN'],
                       GROUP_DISPLAY_ATTRIBUTES, to_group)


def get_non_groups_of(connection, user):
    filter_string = filter_format(app.config['NON_GROUPS_OF_FILTER'],
                                  (user.dn,))
    return get_objects(connection, filter_string, app.config['GROUP_BASE_DN'],
                       GROUP_DISPLAY_ATTRIBUTES, to_group)


def get_groups(connection):
    return get_objects(connection, app.config['GROUPS_FILTER'],
                       app.config['GROUP_BASE_DN'], GROUP_DISPLAY_ATTRIBUTES,
                       to_group)


def request_wants_json():
    best = request.accept_mimetypes \
        .best_match(['application/json', 'text/html'])
    return best == 'application/json' and \
        request.accept_mimetypes[best] > \
        request.accept_mimetypes['text/html']


class DNSelectForm(Form):
    dns = SelectMultipleField("dummy", validators=[
        DataRequired(u"Auswahl erforderlich")])


@app.route('/users/view/<string:uid>')
@with_connection
def view_user(uid, connection):
    user = get_user(connection, uid)
    groups = get_groups_of(connection, user)
    form = DNSelectForm()
    return render_template('user_view.html', user=user, groups=groups,
                           form=form)


@app.route('/groups/view/<string:cn>')
@with_connection
def view_group(cn, connection):
    group = get_group(connection, cn)
    users = get_members(connection, group)
    form = DNSelectForm()
    return render_template('group_view.html', group=group, users=users,
                           form=form)


@app.route('/users/edit/<string:uid>')
@with_connection
def edit_user(uid, connection):
    return redirect(url_for())


@app.route('/groups/edit/<string:cn>')
@with_connection
def edit_group(cn, connection):
    return redirect(url_for())


@app.route('/users/delete/<string:uid>')
@with_connection
def delete_user(uid, connection):
    user = get_user(connection, uid)
    connection.delete_s(user.dn)
    return redirect(url_for('.list_users'))


@app.route('/groups/delete/<string:cn>')
@with_connection
def delete_group(cn, connection):
    group = get_group(connection, cn)
    connection.delete_s(group.dn)
    return redirect(url_for('.list_groups'))


@app.route('/groups/add-members/<string:cn>',
           methods=['GET', 'POST'])
@with_connection
def add_members(cn, connection):
    form = DNSelectForm()
    group = get_group(connection, cn)
    users = get_non_members(connection, group)
    form.dns.choices = [(u.dn, u.uid) for u in users]
    if form.validate_on_submit():
        values = map(operator.methodcaller('encode', 'utf8'), form.dns.data)
        connection.modify_s(group.dn, [(ldap.MOD_ADD, 'member', values)])
        return redirect(url_for('.view_group', cn=cn))
    return render_template("group_add_members.html", group=group, form=form)


@app.route('/groups/remove-members/<string:cn>', methods=['POST'])
@with_connection
def remove_members(cn, connection):
    group = get_group(connection, cn)
    users = get_members(connection, group)
    form = DNSelectForm()
    form.dns.choices = [(u.dn, u.uid) for u in users]
    if not form.is_submitted():
        abort(400)
    if form.validate():
        values = map(operator.methodcaller('encode', 'utf8'), form.dns.data)
        connection.modify_s(group.dn, [(ldap.MOD_DELETE, 'member', values)])
        return redirect(url_for('.view_group', cn=cn))
    return render_template('group_remove_members.html', form=form)


@app.route('/users/add-to-groups/<string:uid>',
           methods=['GET', 'POST'])
@with_connection
def add_to_groups(uid, connection):
    form = DNSelectForm()
    user = get_user(connection, uid)
    groups = get_non_groups_of(connection, user)
    form.dns.choices = [(g.dn, g.cn) for g in groups]
    if form.validate_on_submit():
        values = map(operator.methodcaller('encode', 'utf8'), form.dns.data)
        connection.modify_s(user.dn, [(ldap.MOD_ADD, 'memberOf', values)])
        return redirect(url_for('.view_user', uid=uid))
    return render_template("user_add_groups.html", user=user, form=form)


@app.route('/users/remove-from-groups/<string:uid>', methods=['POST'])
@with_connection
def remove_from_groups(uid, connection):
    group = get_group(connection, uid)
    users = get_members(connection, uid)
    form = DNSelectForm()
    form.dns.choices = [(u.dn, u.uid) for u in users]
    if not form.is_submitted():
        abort(400)
    if form.validate():
        values = map(operator.methodcaller('encode', 'utf8'), form.dns.data)
        connection.modify_s(group.dn, [(ldap.MOD_DELETE, 'member', values)])
        return redirect(url_for('.view_group', cn=uid))
    return render_template('group_remove_members.html', form=form)


def user_to_json(user):
    user_dict = user._asdict()
    user_dict['createTimestamp'] = format_datetime(user.createTimestamp)
    user_dict['modifyTimestamp'] = format_datetime(user.modifyTimestamp)
    user_dict.update(actions={
        'view': url_for('.view_user', uid=user.uid),
        'edit': url_for('.edit_user', uid=user.uid),
        'delete': url_for('.delete_user', uid=user.uid),
    })
    return user_dict


def group_to_json(group):
    group_dict = group._asdict()
    group_dict['createTimestamp'] = format_datetime(group.createTimestamp)
    group_dict['modifyTimestamp'] = format_datetime(group.modifyTimestamp)
    group_dict.update(actions={
        'view': url_for('.view_group', cn=group.cn),
        'edit': url_for('.edit_group', cn=group.cn),
        'delete': url_for('.delete_group', cn=group.cn),
    })
    return group_dict


@app.route('/users')
@with_connection
def list_users(connection):
    if request_wants_json():
        users = get_users(connection)
        return jsonify(items=map(user_to_json, users))
    return render_template('users.html')


@app.route('/groups')
@with_connection
def list_groups(connection):
    if request_wants_json():
        groups = get_groups(connection)
        return jsonify(items=map(group_to_json, groups))
    return render_template('groups.html')


@app.route('/users/groups-of/<string:uid>')
@with_connection
def list_groups_of(uid, connection):
    if not request_wants_json():
        abort(400)
    user = get_user(connection, uid)
    groups = get_groups_of(connection, user)
    return jsonify(items=map(group_to_json, groups))


@app.route('/users/non-groups-of/<string:uid>')
@with_connection
def list_non_groups_of(uid, connection):
    if not request_wants_json():
        abort(400)
    user = get_user(connection, uid)
    groups = get_non_groups_of(connection, user)
    return jsonify(items=map(group_to_json, groups))


@app.route('/groups/members/<string:cn>')
@with_connection
def list_members(cn, connection):
    if not request_wants_json():
        abort(400)
    group = get_group(connection, cn)
    users = get_members(connection, group)
    return jsonify(items=map(user_to_json, users))


@app.route('/groups/non-members/<string:cn>')
@with_connection
def list_non_members(cn, connection):
    if not request_wants_json():
        abort(400)
    group = get_group(connection, cn)
    users = get_non_members(connection, group)
    return jsonify(items=map(user_to_json, users))


class UserForm(Form):
    uid = StringField(u"Login", validators=[DataRequired()])
    givenName = StringField(u"Vorname", validators=[DataRequired()])
    sn = StringField(u"Nachname", validators=[DataRequired()])
    userPassword = PasswordField(u"Passwort", validators=[DataRequired()])
    userPassword_confirmation = PasswordField(
        u"Passwort bestätigen",
        validators=[DataRequired(), EqualTo('userPassword')])
    mail = EmailField(u"E-Mail", validators=[Email()])
    mobile = TelField(u"Handy")


def encrypt_password(password):
    return passlib.hash.ldap_sha512_crypt.encrypt(password)


@app.route('/users/create', methods=['GET', 'POST'])
@with_connection
def create_user(connection):
    form = UserForm()
    if form.validate_on_submit():
        uid = escape_dn_chars(form.uid.data.encode('utf8'))
        sn = form.sn.data.encode('utf8')
        givenName = form.givenName.data.encode('utf8')
        cn = '{0} {1}'.format(givenName, sn)
        password = encrypt_password(form.userPassword.data.encode('utf8'))
        entry = {
            'objectClass': ['inetOrgPerson'],
            'uid': uid,
            'sn': sn,
            'givenName': givenName,
            'cn': cn,
            'userPassword': password,
            'mail': form.mail.data.encode('utf8'),
        }
        dn = app.config['USER_DN_TEMPLATE'] % entry
        try:
            connection.add_s(dn, ldap.modlist.addModlist(entry))
        except ldap.ALREADY_EXISTS:
            raise LDAPError(u"Benutzer mit Login '{0}' "
                            u"bereits vorhanden.".format(uid))
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
        entry = {
            'objectClass': ['groupOfMembers'],
            'cn': cn,
        }
        dn = app.config['GROUP_DN_TEMPLATE'] % entry
        try:
            connection.add_s(dn, ldap.modlist.addModlist(entry))
        except ldap.ALREADY_EXISTS:
            raise LDAPError(u"Gruppe mit Name '{0}' "
                            u"bereits vorhanden.".format(cn))
        return redirect(url_for('.view_group', cn=cn))
    return render_template('group_create.html', form=form)


if __name__ == '__main__':
    app.run()