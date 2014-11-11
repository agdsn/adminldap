# coding=utf8
import collections
from datetime import datetime
from itertools import chain, imap
import operator

from flask import (
    Flask, abort, redirect, render_template, request, url_for, jsonify,
    make_response, flash)
from flask.views import View
from flask_login import current_user, LoginManager, UserMixin
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
from wtforms import (
    PasswordField, SelectMultipleField, StringField, TextAreaField)
from wtforms.validators import DataRequired, Email, EqualTo, Length


app = Flask('adminldap')
app.config.from_pyfile('app.cfg')
login_manager = LoginManager()
login_manager.init_app(app)
babel = Babel()
babel.init_app(app)
app.jinja_env.globals['OrderedDict'] = collections.OrderedDict

USER_DISPLAY_ATTRIBUTES = ['uid', 'givenName', 'sn', 'mail', 'mobile',
                           'createTimestamp', 'modifyTimestamp']
GROUP_DISPLAY_ATTRIBUTES = ['cn', 'description',
                            'createTimestamp', 'modifyTimestamp']
LDAP_TIME_FORMAT = '%Y%m%d%H%M%SZ'


User = collections.namedtuple('User', (
    'dn', 'uid', 'givenName', 'sn', 'userPassword', 'mail', 'mobile',
    'createTimestamp', 'modifyTimestamp'))

Group = collections.namedtuple('Group', (
    'dn', 'cn', 'description', 'createTimestamp', 'modifyTimestamp'))


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
        try:
            user = get_user(conn, uid)
        except NoResults:
            return None

    try:
        with pool.connection(user.dn, auth.password) as conn:
            return AppUser(*user)
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


@app.before_request
def before_request():
    if not current_user.is_authenticated():
        return login_manager.unauthorized()


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
    return render_template('error.html', message=message, code=code), code


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
        connection.protocol_version = ldap.VERSION3
        connection.timeout = app.config['LDAP_TIMEOUT']
        kwargs['connection'] = connection
        return wrapped(*args, **kwargs)


class UserPasswordForm(Form):
    userPassword = PasswordField(u"Passwort",
                                 validators=[DataRequired(), Length(min=8)])
    userPassword_confirm = PasswordField(u"Passwort bestätigen",
                                         validators=[EqualTo("userPassword")])


class UserDetailsForm(Form):
    givenName = StringField(u"Vorname", validators=[DataRequired()])
    sn = StringField(u"Nachname", validators=[DataRequired()])
    mail = EmailField(u"E-Mail", validators=[DataRequired(), Email()])
    mobile = TelField(u"Handy")


class SelfView(View):
    methods = ['GET', 'POST']

    def __init__(self):
        self.user = None
        self.connection = None
        self.password_form = None
        self.details_form = None

    @with_connection
    def dispatch_request(self, connection):
        self.connection = connection
        self.user = current_user
        self.password_form = UserPasswordForm(formdata=None)
        self.details_form = UserDetailsForm(formdata=None, obj=self.user)
        action = request.args.get('action')
        if action == 'update-password':
            self.update_password()
        elif action == 'update-details':
            self.update_details()
        return render_template('self.html', user=current_user,
                               password_form=self.password_form,
                               details_form=self.details_form)

    def update_password(self):
        self.password_form.process(formdata=request.form)
        if self.password_form.validate_on_submit():
            password = self.password_form.userPassword.data.encode('utf8')
            encrypted_password = encrypt_password(password)
            mod_list = [(ldap.MOD_REPLACE, 'userPassword', encrypted_password)]
            self.connection.modify_s(self.user.dn, mod_list)
            flash(u"Passwort erfolgreich geändert.", "success")

    def update_details(self):
        self.details_form.process(formdata=request.form, obj=current_user)
        if self.details_form.validate_on_submit():
            mod_list = mod_list_from_form(current_user, self.details_form,
                                          ['givenName', 'sn', 'mail', 'mobile'])
            self.connection.modify_s(current_user.dn, mod_list)
            flash(u"Details erfolgreich geändert.", "success")


app.add_url_rule('/', view_func=SelfView.as_view('manage_self'))
app.add_url_rule('/self', endpoint='manage_self')


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
    return Group(dn, entry['cn'][0], get_or_none(entry, 'description'),
                 created_at, modified_at)


def to_dn(res_data):
    dn, entry = res_data
    return dn


def get_single_object(connection, filter_string, base, attributes, creator):
    try:
        entries = connection.search_st(base, ldap.SCOPE_SUBTREE, filter_string,
                                       attributes)
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
    results = imap(to_entries, connection.allresults(msg_id))
    group_entries = chain(*results)
    return imap(creator, group_entries)


def get_user_dn(connection, uid):
    user_filter = filter_format(app.config['USER_FILTER'], (uid,))
    return get_single_object(connection, user_filter,
                             app.config['USER_BASE_DN'], [], to_dn)


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


class UserEditView(SelfView):
    methods = ['GET', 'POST']

    def __init__(self):
        super(UserEditView, self).__init__()
        self.add_groups_form = None
        self.remove_groups_form = None

    def modify_groups(self, mod_type, group_dns=None):
        messages = set()
        for group in imap(operator.methodcaller('encode', 'utf8'), group_dns):
            mod_list = [(mod_type, 'member', [self.user.dn])]
            messages.add(self.connection.modify(group, mod_list))
        while messages:
            res_type, res_data, res_msg_id = self.connection.result2()
            assert res_msg_id in messages
            messages.remove(res_msg_id)

    def add_groups(self):
        self.details_form.process(obj=self.user)
        self.add_groups_form.process(formdata=request.form)
        groups = get_non_groups_of(self.connection, self.user)
        self.add_groups_form.dns.choices = [(g.dn, g.cn) for g in groups]
        if self.add_groups_form.validate_on_submit():
            self.modify_groups(ldap.MOD_ADD, self.add_groups_form.dns.data)
            flash(u"Gruppen erfolgreich hinzugefügt.", "success")

    def remove_groups(self):
        self.details_form.process(obj=self.user)
        self.remove_groups_form.process(formdata=request.form)
        groups = get_groups_of(self.connection, self.user)
        self.remove_groups_form.dns.choices = [(g.dn, g.cn) for g in groups]
        if self.remove_groups_form.validate_on_submit():
            self.modify_groups(ldap.MOD_DELETE,
                               self.remove_groups_form.dns.data)
            flash(u"Gruppen erfolgreich entfernt.", "success")

    @with_connection
    def dispatch_request(self, uid, connection):
        action = request.args.get('action')
        self.connection = connection
        self.user = get_user(connection, uid)
        self.details_form = UserDetailsForm(formdata=None, obj=self.user)
        self.password_form = UserPasswordForm(formdata=None)
        self.add_groups_form = DNSelectForm(formdata=None)
        self.remove_groups_form = DNSelectForm(formdata=None)
        if action == 'update-details':
            self.update_details()
        elif action == 'update-password':
            self.update_password()
        elif action == 'add-groups':
            self.add_groups()
        elif action == 'remove-groups':
            self.remove_groups()
        return render_template('user_edit.html', user=self.user,
                               details_form=self.details_form,
                               password_form=self.password_form,
                               add_groups_form=self.add_groups_form,
                               remove_groups_form=self.remove_groups_form)


app.add_url_rule('/users/edit/<string:uid>',
                 view_func=UserEditView.as_view('edit_user'))


def mod_list_from_form(obj, form, attributes):
    old_entry = {
        attr: getattr(obj, attr)
        for attr in attributes
        if getattr(obj, attr) is not None}
    new_entry = {
        attr: getattr(form, attr).data.encode('utf8')
        for attr in attributes
        if getattr(form, attr).data
    }
    return ldap.modlist.modifyModlist(old_entry, new_entry)


class GroupForm(Form):
    cn = StringField(u"Name",
                     validators=[DataRequired(), Length(3, 256)])
    description = TextAreaField(u"Beschreibung", validators=[Length(max=1024)])


class GroupEditView(View):
    methods = ['GET', 'POST']

    def __init__(self):
        self.connection = None
        self.group = None
        self.details_form = None
        self.add_members_form = None
        self.remove_members_form = None

    def update_details(self):
        self.details_form.process(formdata=request.form, obj=self.group)
        if self.details_form.validate_on_submit():
            mod_list = mod_list_from_form(self.group, self.details_form,
                                          ['description'])
            self.connection.modify_s(self.group.dn, mod_list)
            cn = self.details_form.cn.data.encode('utf8')
            if cn != self.group.cn:
                self.connection.rename_s(self.group.dn,
                                         "cn=" + escape_dn_chars(cn))
            flash(u"Details erfolgreich geändert.", "success")

    def add_members(self):
        users = get_non_members(self.connection, self.group)
        self.add_members_form.dns.choices = [(u.dn, u.uid) for u in users]
        self.add_members_form.process(formdata=request.form)
        if self.add_members_form.validate_on_submit():
            mod_list = [(ldap.MOD_ADD, 'member',
                         map(operator.methodcaller('encode', 'utf8'),
                             self.add_members_form.dns.data))]
            self.connection.modify_s(self.group.dn, mod_list)
            flash(u"Mitglieder erfolgreich hinzugefügt.", "success")

    def remove_members(self):
        users = get_members(self.connection, self.group)
        self.remove_members_form.dns.choices = [(u.dn, u.uid) for u in users]
        self.remove_members_form.process(formdata=request.form)
        if self.remove_members_form.validate_on_submit():
            mod_list = [(ldap.MOD_DELETE, 'member',
                         map(operator.methodcaller('encode', 'utf8'),
                             self.remove_members_form.dns.data))]
            self.connection.modify_s(self.group.dn, mod_list)
            flash(u"Mitglieder erfolgreich entfernt.", "success")

    @with_connection
    def dispatch_request(self, cn, connection):
        action = request.args.get('action')
        self.connection = connection
        self.group = get_group(connection, cn)
        self.details_form = GroupForm(formdata=None, obj=self.group)
        self.add_members_form = DNSelectForm(formdata=None)
        self.remove_members_form = DNSelectForm(formdata=None)
        if action == 'update-details':
            self.update_details()
        elif action == 'add-members':
            self.add_members()
        elif action == 'remove-members':
            self.remove_members()
        return render_template('group_edit.html', group=self.group,
                               details_form=self.details_form,
                               add_members_form=self.add_members_form,
                               remove_members_form=self.remove_members_form)

app.add_url_rule('/groups/edit/<string:cn>',
                 view_func=GroupEditView.as_view('edit_group'))


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


def user_to_json(user):
    user_dict = user._asdict()
    user_dict['createTimestamp'] = format_datetime(user.createTimestamp)
    user_dict['modifyTimestamp'] = format_datetime(user.modifyTimestamp)
    user_dict.update(actions={
        'edit': url_for('.edit_user', uid=user.uid),
        'delete': url_for('.delete_user', uid=user.uid),
    })
    return user_dict


def group_to_json(group):
    group_dict = group._asdict()
    group_dict['createTimestamp'] = format_datetime(group.createTimestamp)
    group_dict['modifyTimestamp'] = format_datetime(group.modifyTimestamp)
    group_dict.update(actions={
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


class UserCreateForm(Form):
    uid = StringField(u"Login", validators=[DataRequired()])
    givenName = StringField(u"Vorname", validators=[DataRequired()])
    sn = StringField(u"Nachname", validators=[DataRequired()])
    userPassword = PasswordField(u"Passwort",
                                 validators=[DataRequired(), Length(min=8)])
    userPassword_confirmation = PasswordField(
        u"Passwort bestätigen",
        validators=[DataRequired(), EqualTo('userPassword')])
    mail = EmailField(u"E-Mail", validators=[DataRequired(), Email()])
    mobile = TelField(u"Handy")


def encrypt_password(password):
    return passlib.hash.ldap_sha512_crypt.encrypt(password)


@app.route('/users/create', methods=['GET', 'POST'])
@with_connection
def create_user(connection):
    form = UserCreateForm()
    if form.validate_on_submit():
        uid = form.uid.data.encode('utf8')
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
            'mobile': form.mobile.data.encode('utf8'),
        }
        dn = app.config['USER_DN_TEMPLATE'] % {'uid': escape_dn_chars(uid)}
        try:
            connection.add_s(dn, ldap.modlist.addModlist(entry))
        except ldap.ALREADY_EXISTS:
            raise LDAPError(u"Benutzer mit Login '{0}' "
                            u"bereits vorhanden.".format(uid))
        return redirect(url_for('.edit_user', uid=uid))
    return render_template('user_create.html', form=form)


@app.route('/groups/create', methods=['GET', 'POST'])
@with_connection
def create_group(connection):
    form = GroupForm()
    if form.validate_on_submit():
        cn = form.cn.data.encode('utf8')
        entry = {
            'objectClass': ['groupOfMembers'],
            'cn': cn,
            'description': form.description.data.encode('utf8'),
        }
        dn = app.config['GROUP_DN_TEMPLATE'] % {'cn', escape_dn_chars(cn)}
        try:
            connection.add_s(dn, ldap.modlist.addModlist(entry))
        except ldap.ALREADY_EXISTS:
            raise LDAPError(u"Gruppe mit Name '{0}' "
                            u"bereits vorhanden.".format(cn))
        return redirect(url_for('.edit_group', cn=cn))
    return render_template('group_create.html', form=form)


if __name__ == '__main__':
    app.run()