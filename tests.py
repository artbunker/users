import sys
import unittest
import uuid
import time
from datetime import datetime, timezone

from ipaddress import ip_address
from sqlalchemy import create_engine

from testhelper import TestHelper, compare_base_attributes
from base64_url import base64_url_encode, base64_url_decode
from users import Users, UserStatus, User, Invite, Session, Authentication
from users import Permission, AutoPermission, parse_id

db_url = ''

class TestUsers(TestHelper):
	def setUp(self):
		if db_url:
			engine = create_engine(db_url)
		else:
			engine = create_engine('sqlite:///:memory:')

		self.users = Users(
			engine,
			install=True,
			db_prefix=base64_url_encode(uuid.uuid4().bytes),
		)

	def tearDown(self):
		if db_url:
			self.users.uninstall()

	def assert_non_user_raises(self, f):
		# any non-user object should raise
		for invalid_user in [
				'string',
				1,
				['list'],
				{'dict': 'ionary'},
			]:
			with self.assertRaises(Exception):
				f(invalid_user)

	def test_parse_id(self):
		for invalid_input in [
				'contains non base64_url characters $%^~',
				['list'],
				{'dict': 'ionary'},
			]:
			with self.assertRaises(Exception):
				id, id_bytes = parse_id(invalid_input)
		expected_bytes = uuid.uuid4().bytes
		expected_string = base64_url_encode(expected_bytes)
		# from bytes
		id, id_bytes = parse_id(expected_bytes)
		self.assertEqual(id_bytes, expected_bytes)
		self.assertEqual(id, expected_string)
		# from string
		id, id_bytes = parse_id(expected_string)
		self.assertEqual(id, expected_string)
		self.assertEqual(id_bytes, expected_bytes)

	# class instantiation, create, get, and defaults
	def test_user_class_create_get_and_defaults(self):
		self.class_create_get_and_defaults(
			User,
			self.users.create_user,
			self.users.get_user,
			{
				'status': UserStatus.AWAITING_ACTIVATION,
				'name': '',
				'display': '',
				'last_seen_time': 0,
				'protected': False,
			},
		)

	def test_invite_class_create_get_and_defaults(self):
		self.class_create_get_and_defaults(
			Invite,
			self.users.create_invite,
			self.users.get_invite,
			{
				'redeem_time': 0,
				'created_by_user_id': '',
				'created_by_user_id_bytes': base64_url_decode(''),
				'created_by_user': None,
				'redeemed_by_user_id': '',
				'redeemed_by_user_id_bytes': base64_url_decode(''),
				'redeemed_by_user': None,
			},
		)

	def test_session_class_create_get_and_defaults(self):
		self.class_create_get_and_defaults(
			Session,
			self.users.create_session,
			self.users.get_session,
			{
				'user_id': '',
				'user_id_bytes': base64_url_decode(''),
				'user': None,
				'remote_origin': ip_address('127.0.0.1'),
				'useragent_id': '',
				'useragent_id_bytes': base64_url_decode(''),
				'close_time': 0,
				'useragent_id': '',
				'useragent_id_bytes': base64_url_decode(''),
				'useragent': '',
			},
		)

	def test_authentication_class_create_get_and_defaults(self):
		self.class_create_get_and_defaults(
			Authentication,
			self.users.create_authentication,
			self.users.get_authentication,
			{
				'user_id': '',
				'user_id_bytes': base64_url_decode(''),
				'user': None,
				'service': '',
				'value': '',
			},
		)

	def test_permission_class_create_get_and_defaults(self):
		self.class_create_get_and_defaults(
			Permission,
			self.users.create_permission,
			self.users.get_permission,
			{
				'user_id': '',
				'user_id_bytes': base64_url_decode(''),
				'user': None,
				'scope': '',
				'group_bits': (0).to_bytes(2, 'big'),
			},
		)

	def test_auto_permission_class_create_get_and_defaults(self):
		self.class_create_get_and_defaults(
			AutoPermission,
			self.users.create_auto_permission,
			self.users.get_auto_permission,
			{
				'user_id': '',
				'user_id_bytes': base64_url_decode(''),
				'user': None,
				'scope': '',
				'group_bits': (0).to_bytes(2, 'big'),
				'group_names': [],
				'duration': 0,
				'valid_until_time': 0,
				'created_by_user_id': '',
				'created_by_user_id_bytes': base64_url_decode(''),
				'created_by_user': None,
			},
		)

	#TODO assert properties that default to current time
	#TODO assert properties that default to uuid bytes

	# avoiding collision during testing for creating multiple objects without
	# specifying certain unique properties manually
	def create_unique_user(self, **kwargs):
		# create user with unique name and display to avoid collision
		if 'name' not in kwargs:
			kwargs['name'] = base64_url_encode(uuid.uuid4().bytes)
		if 'display' not in kwargs:
			kwargs['display'] = base64_url_encode(uuid.uuid4().bytes)
		return self.users.create_user(**kwargs)

	def create_unique_authentication(self, **kwargs):
		# create authentication with unique user id and scope to avoid collision
		if 'user_id' not in kwargs:
			kwargs['user_id'] = uuid.uuid4().bytes
		if 'service' not in kwargs:
			kwargs['service'] = base64_url_encode(uuid.uuid4().bytes)
		return self.users.create_authentication(**kwargs)

	def create_unique_permission(self, **kwargs):
		# create permission with unique user id and scope to avoid collision
		if 'user_id' not in kwargs:
			kwargs['user_id'] = uuid.uuid4().bytes
		if 'scope' not in kwargs:
			kwargs['scope'] = base64_url_encode(uuid.uuid4().bytes)
		return self.users.create_permission(**kwargs)

	# class instantiation and db object creation with properties
	# id properties
	def test_user_id_property(self):
		self.id_property(User, self.users.create_user, 'id')

	def test_invite_id_property(self):
		self.id_property(User, self.users.create_invite, 'id')

	def test_invite_created_by_user_id_property(self):
		self.id_property(Invite, self.users.create_invite, 'created_by_user_id')

	def test_invite_redeemed_by_user_id_property(self):
		self.id_property(Invite, self.users.create_invite, 'redeemed_by_user_id')

	def test_session_id_property(self):
		self.id_property(Session, self.users.create_session, 'id')

	def test_session_user_id_property(self):
		self.id_property(Session, self.users.create_session, 'user_id')

	def test_authentication_id_property(self):
		# using create_unique_authentication to ensure exceptions raised are due
		# to invalid id, not authentication collisions
		self.id_property(Authentication, self.create_unique_authentication, 'id')

	def test_authentication_user_id_property(self):
		# using create_unique_authentication to ensure exceptions raised are due
		# to invalid id, not authentication collisions
		self.id_property(
			Authentication,
			self.create_unique_authentication,
			'user_id',
		)

	def test_permission_id_property(self):
		self.id_property(Permission, self.users.create_permission, 'id')

	def test_permission_user_id_property(self):
		self.id_property(Permission, self.users.create_permission, 'user_id')

	def test_auto_permission_id_property(self):
		self.id_property(AutoPermission, self.users.create_auto_permission, 'id')

	def test_auto_permission_user_id_property(self):
		self.id_property(
			AutoPermission,
			self.users.create_auto_permission,
			'user_id',
		)

	def test_auto_permission_created_by_user_id_property(self):
		self.id_property(
			AutoPermission,
			self.users.create_auto_permission,
			'created_by_user_id',
		)

	# time properties
	def test_user_creation_time_property(self):
		self.time_property(User, self.create_unique_user, 'creation')

	def test_user_touch_time_property(self):
		self.time_property(User, self.create_unique_user, 'touch')

	# user last seen time is dependent on attached sessions
	# and isn't created on users directly

	def test_invite_creation_time_property(self):
		self.time_property(Invite, self.users.create_invite, 'creation')

	def test_invite_redeem_time_property(self):
		self.time_property(Invite, self.users.create_invite, 'redeem')

	def test_session_creation_time_property(self):
		self.time_property(Session, self.users.create_session, 'creation')

	def test_session_touch_time_property(self):
		self.time_property(Session, self.users.create_session, 'touch')

	def test_session_close_time_property(self):
		self.time_property(Session, self.users.create_session, 'close')

	def test_authentication_creation_time_property(self):
		self.time_property(
			Authentication,
			self.create_unique_authentication,
			'creation',
		)

	def test_permission_creation_time_property(self):
		self.time_property(
			Permission,
			self.create_unique_permission,
			'creation',
		)

	def test_auto_permission_creation_time_property(self):
		self.time_property(
			AutoPermission,
			self.users.create_auto_permission,
			'creation',
		)

	def test_auto_permission_valid_from_time_property(self):
		self.time_property(
			AutoPermission,
			self.users.create_auto_permission,
			'valid_from',
		)

	def test_auto_permission_valid_until_time_property(self):
		self.time_property(
			AutoPermission,
			self.users.create_auto_permission,
			'valid_until',
		)

	# bool properties

	# user protected is dependent on using protect_user/unprotect_user
	# and isn't created on users directly

	def test_authentication_forbidden_bool_property(self):
		self.bool_property(
			Authentication,
			self.create_unique_authentication,
			'forbidden',
		)

	# string properties

	# user name has specific restrictions tested below

	def test_user_display_property(self):
		self.string_property(
			User,
			self.users.create_user,
			'display',
		)

	def test_session_useragent_property(self):
		self.string_property(
			Session,
			self.users.create_session,
			'useragent',
		)

	def test_authentication_service_property(self):
		# using create_unique_authentication to ensure exceptions raised are due
		# to invalid service, not authentication collisions
		self.string_property(
			Authentication,
			self.create_unique_authentication,
			'service',
		)

	def test_permission_scope_property(self):
		# using create_unique_permission to ensure exceptions raised are due
		# to invalid scope, not permission collisions
		self.string_property(
			Permission,
			self.create_unique_permission,
			'scope',
		)

	def test_auto_permission_scope_property(self):
		self.string_property(
			AutoPermission,
			self.users.create_auto_permission,
			'scope',
		)

	# delete
	def test_delete_user(self):
		self.delete(
			self.users.create_user,
			self.users.get_user,
			self.users.delete_user,
		)

	def test_delete_invite(self):
		self.delete(
			self.users.create_invite,
			self.users.get_invite,
			self.users.delete_invite,
		)

	def test_delete_session(self):
		self.delete(
			self.users.create_session,
			self.users.get_session,
			self.users.delete_session,
		)

	def test_delete_authentication(self):
		self.delete(
			self.users.create_authentication,
			self.users.get_authentication,
			self.users.delete_authentication,
		)

	def test_delete_permission(self):
		self.delete(
			self.users.create_permission,
			self.users.get_permission,
			self.users.delete_permission,
		)

	def test_delete_auto_permission(self):
		self.delete(
			self.users.create_auto_permission,
			self.users.get_auto_permission,
			self.users.delete_auto_permission,
		)

	# id collision
	def test_users_id_collision(self):
		self.id_collision(self.users.create_user)

	def test_invites_id_collision(self):
		self.id_collision(self.users.create_invite)

	def test_sessions_id_collision(self):
		self.id_collision(self.users.create_session)

	def test_authentications_id_collision(self):
		# using create_unique_authentication to ensure exceptions raised are due
		# to actual id collision, not authentication collisions
		self.id_collision(self.create_unique_authentication)

	def test_permissions_id_collision(self):
		self.id_collision(self.users.create_permission)

	def test_auto_permissions_id_collision(self):
		self.id_collision(self.users.create_auto_permission)

	# unfiltered count
	def test_count_users(self):
		self.count(
			self.users.create_user,
			self.users.count_users,
			self.users.delete_user,
		)

	def test_count_invites(self):
		self.count(
			self.users.create_invite,
			self.users.count_invites,
			self.users.delete_invite,
		)

	def test_count_sessions(self):
		self.count(
			self.users.create_session,
			self.users.count_sessions,
			self.users.delete_session,
		)

	def test_count_authentications(self):
		# using create_unique_authentication to avoid collisions
		self.count(
			self.create_unique_authentication,
			self.users.count_authentications,
			self.users.delete_authentication,
		)

	def test_count_permissions(self):
		# using create_unique_permission to avoid collisions
		self.count(
			self.create_unique_permission,
			self.users.count_permissions,
			self.users.delete_permission,
		)

	def test_count_auto_permissions(self):
		self.count(
			self.users.create_auto_permission,
			self.users.count_auto_permissions,
			self.users.delete_auto_permission,
		)

	# unfiltered search
	def test_search_users(self):
		self.search(
			self.users.create_user,
			self.users.search_users,
			self.users.delete_user,
		)

	def test_search_invites(self):
		self.search(
			self.users.create_invite,
			self.users.search_invites,
			self.users.delete_invite,
		)

	def test_search_sessions(self):
		self.search(
			self.users.create_session,
			self.users.search_sessions,
			self.users.delete_session,
		)

	def test_search_authentications(self):
		# using create_unique_authentication to avoid collisions
		self.search(
			self.create_unique_authentication,
			self.users.search_authentications,
			self.users.delete_authentication,
		)

	def test_search_permissions(self):
		# using create_unique_permission to avoid collisions
		self.search(
			self.create_unique_permission,
			self.users.search_permissions,
			self.users.delete_permission,
		)

	def test_search_auto_permissions(self):
		self.search(
			self.users.create_auto_permission,
			self.users.search_auto_permissions,
			self.users.delete_auto_permission,
		)

	# sort order and pagination
	def test_search_users_creation_time_sort_order_and_pagination(self):
		self.search_sort_order_and_pagination(
			self.users.create_user,
			'creation_time',
			self.users.search_users,
		)

	def test_search_users_touch_time_sort_order_and_pagination(self):
		self.search_sort_order_and_pagination(
			self.users.create_user,
			'touch_time',
			self.users.search_users,
		)

	def test_search_users_name_sort_order_and_pagination(self):
		self.search_sort_order_and_pagination(
			self.users.create_user,
			'name',
			self.users.search_users,
			first_value='a',
			middle_value='b',
			last_value='c',
		)

	def test_search_users_display_sort_order_and_pagination(self):
		self.search_sort_order_and_pagination(
			self.users.create_user,
			'display',
			self.users.search_users,
			first_value='a',
			middle_value='b',
			last_value='c',
		)

	def test_search_last_seen_time_sort_order_and_pagination(self):
		# attached sessions must be generated to sort users by last seen time
		def create_user_with_last_seen_time(**kwargs):
			user = self.users.create_user()
			if 'last_seen_time' in kwargs:
				self.users.create_session(
					user_id=user.id,
					touch_time=kwargs['last_seen_time'],
				)
				user = self.users.get_user(user.id)
			return user
		self.search_sort_order_and_pagination(
			create_user_with_last_seen_time,
			'last_seen_time',
			self.users.search_users,
		)

	def test_search_invites_creation_time_sort_order_and_pagination(self):
		self.search_sort_order_and_pagination(
			self.users.create_invite,
			'creation_time',
			self.users.search_invites,
		)

	def test_search_invites_redeem_time_sort_order_and_pagination(self):
		self.search_sort_order_and_pagination(
			self.users.create_invite,
			'redeem_time',
			self.users.search_invites,
		)

	def test_search_sessions_creation_time_sort_order_and_pagination(self):
		self.search_sort_order_and_pagination(
			self.users.create_session,
			'creation_time',
			self.users.search_sessions,
		)

	def test_search_sessions_touch_time_sort_order_and_pagination(self):
		self.search_sort_order_and_pagination(
			self.users.create_session,
			'touch_time',
			self.users.search_sessions,
		)

	def test_search_sessions_close_time_sort_order_and_pagination(self):
		self.search_sort_order_and_pagination(
			self.users.create_session,
			'close_time',
			self.users.search_sessions,
		)

	def test_search_authentications_creation_time_sort_order_and_pagination(
			self,
		):
		# using create_unique_authentication to avoid collisions
		self.search_sort_order_and_pagination(
			self.create_unique_authentication,
			'creation_time',
			self.users.search_authentications,
		)

	def test_search_authentications_service_sort_order_and_pagination(self):
		# using create_unique_authentication to avoid collisions
		self.search_sort_order_and_pagination(
			self.create_unique_authentication,
			'service',
			self.users.search_authentications,
		)

	def test_search_authentications_value_sort_order_and_pagination(self):
		# using create_unique_authentication to avoid collisions
		self.search_sort_order_and_pagination(
			self.create_unique_authentication,
			'value',
			self.users.search_authentications,
			first_value='a',
			middle_value='b',
			last_value='c',
		)

	def test_search_permissions_creation_time_sort_order_and_pagination(self):
		# using create_unique_permission to avoid collisions
		self.search_sort_order_and_pagination(
			self.create_unique_permission,
			'creation_time',
			self.users.search_permissions,
		)

	def test_search_permissions_scope_sort_order_and_pagination(self):
		# using create_unique_permission to avoid collisions
		self.search_sort_order_and_pagination(
			self.create_unique_permission,
			'scope',
			self.users.search_permissions,
			first_value='a',
			middle_value='b',
			last_value='c',
		)

	def test_search_auto_permissions_creation_time_sort_order_and_pagination(
			self,
		):
		self.search_sort_order_and_pagination(
			self.users.create_auto_permission,
			'creation_time',
			self.users.search_auto_permissions,
		)

	def test_search_auto_permissions_scope_sort_order_and_pagination(self):
		self.search_sort_order_and_pagination(
			self.users.create_auto_permission,
			'scope',
			self.users.search_auto_permissions,
			first_value='a',
			middle_value='b',
			last_value='c',
		)

	def test_search_auto_permissions_duration_sort_order_and_pagination(self):
		self.search_sort_order_and_pagination(
			self.users.create_auto_permission,
			'duration',
			self.users.search_auto_permissions,
		)

	def test_search_auto_permissions_valid_from_time_sort_order_and_pagination(
			self,
		):
		self.search_sort_order_and_pagination(
			self.users.create_auto_permission,
			'valid_from_time',
			self.users.search_auto_permissions,
		)

	def test_search_auto_permissions_valid_until_time_sort_order_and_pagination(
			self,
		):
		self.search_sort_order_and_pagination(
			self.users.create_auto_permission,
			'valid_until_time',
			self.users.search_auto_permissions,
		)

	# search by id
	def test_search_users_by_id(self):
		self.search_by_id(
			self.users.create_user,
			'id',
			self.users.search_users,
			'ids',
		)

	def test_search_invites_by_id(self):
		self.search_by_id(
			self.users.create_invite,
			'id',
			self.users.search_invites,
			'ids',
		)

	def test_search_invites_by_created_by_user_id(self):
		self.search_by_id(
			self.users.create_invite,
			'created_by_user_id',
			self.users.search_invites,
			'created_by_user_ids',
		)

	def test_search_invites_by_redeemed_by_user_id(self):
		self.search_by_id(
			self.users.create_invite,
			'redeemed_by_user_id',
			self.users.search_invites,
			'redeemed_by_user_ids',
		)

	def test_search_sessions_by_id(self):
		self.search_by_id(
			self.users.create_session,
			'id',
			self.users.search_sessions,
			'ids',
		)

	def test_search_sessions_by_useragent_id(self):
		id1 = self.users.create_useragent('Mozilla')
		id2 = self.users.create_useragent('Bot')
		self.search_by_id(
			self.users.create_session,
			'useragent_id',
			self.users.search_sessions,
			'useragent_ids',
			id1=id1,
			id2=id2,
		)

	def test_search_sessions_by_user_id(self):
		self.search_by_id(
			self.users.create_session,
			'user_id',
			self.users.search_sessions,
			'user_ids',
		)

	def test_search_authentications_by_id(self):
		# using create_unique_authentication to avoid collisions
		self.search_by_id(
			self.create_unique_authentication,
			'id',
			self.users.search_authentications,
			'ids',
		)

	def test_search_authentications_by_user_id(self):
		# using create_unique_authentication to avoid collisions
		self.search_by_id(
			self.create_unique_authentication,
			'user_id',
			self.users.search_authentications,
			'user_ids',
		)

	def test_search_permissions_by_id(self):
		# using create_unique_permission to avoid collisions
		self.search_by_id(
			self.create_unique_permission,
			'id',
			self.users.search_permissions,
			'ids',
		)

	def test_search_permissions_by_user_id(self):
		self.search_by_id(
			self.users.create_permission,
			'user_id',
			self.users.search_permissions,
			'user_ids',
		)

	def test_search_auto_permissions_by_id(self):
		self.search_by_id(
			self.users.create_auto_permission,
			'id',
			self.users.search_auto_permissions,
			'ids',
		)

	def test_search_auto_permissions_by_user_id(self):
		self.search_by_id(
			self.users.create_auto_permission,
			'user_id',
			self.users.search_auto_permissions,
			'user_ids',
		)

	def test_search_auto_permissions_by_created_by_user_id(self):
		self.search_by_id(
			self.users.create_auto_permission,
			'created_by_user_id',
			self.users.search_auto_permissions,
			'created_by_user_ids',
		)

	# search by time
	def search_users_by_creation_time(self):
		self.search_by_time_cutoff(
			self.users.create_user,
			'creation_time',
			self.users.search_users,
			'created',
		)

	def test_search_users_by_touch_time(self):
		self.search_by_time_cutoff(
			self.users.create_user,
			'touch_time',
			self.users.search_users,
			'touched',
		)

	def test_search_invites_by_creation_time(self):
		self.search_by_time_cutoff(
			self.users.create_invite,
			'creation_time',
			self.users.search_invites,
			'created',
		)

	def test_search_invitess_by_redeem_time(self):
		self.search_by_time_cutoff(
			self.users.create_invite,
			'redeem_time',
			self.users.search_invites,
			'redeemed',
		)

	def test_search_sessions_by_creation_time(self):
		self.search_by_time_cutoff(
			self.users.create_session,
			'creation_time',
			self.users.search_sessions,
			'created',
		)

	def test_search_sessions_by_touch_time(self):
		self.search_by_time_cutoff(
			self.users.create_session,
			'touch_time',
			self.users.search_sessions,
			'touched',
		)

	def test_search_sessions_by_close_time(self):
		self.search_by_time_cutoff(
			self.users.create_session,
			'close_time',
			self.users.search_sessions,
			'closed',
		)

	def test_search_authentications_by_creation_time(self):
		# using create_unique_authentication to avoid collisions
		self.search_by_time_cutoff(
			self.create_unique_authentication,
			'creation_time',
			self.users.search_authentications,
			'created',
		)

	def test_search_permissions_by_creation_time(self):
		# using create_unique_permission to avoid collisions
		self.search_by_time_cutoff(
			self.create_unique_permission,
			'creation_time',
			self.users.search_permissions,
			'created',
		)

	def test_search_auto_permissions_by_creation_time(self):
		self.search_by_time_cutoff(
			self.users.create_auto_permission,
			'creation_time',
			self.users.search_auto_permissions,
			'created',
		)

	def test_search_auto_permissions_by_valid_from_time(self):
		self.search_by_time_cutoff(
			self.users.create_auto_permission,
			'valid_from_time',
			self.users.search_auto_permissions,
			'valid_from',
		)

	def test_search_auto_permissions_by_valid_until_time(self):
		self.search_by_time_cutoff(
			self.users.create_auto_permission,
			'valid_until_time',
			self.users.search_auto_permissions,
			'valid_until',
		)

	# search by string like
	def test_search_users_by_name(self):
		self.search_by_string_like(
			self.users.create_user,
			'name',
			self.users.search_users,
			'names',
		)

	def test_search_users_by_display(self):
		self.search_by_string_like(
			self.users.create_user,
			'display',
			self.users.search_users,
			'displays',
		)

	def test_search_authentication_by_value(self):
		# using create_unique_authentication to avoid collisions
		self.search_by_string_like(
			self.create_unique_authentication,
			'value',
			self.users.search_authentications,
			'values',
		)

	# search by string equal
	def test_search_authentications_by_service(self):
		self.search_by_string_equal(
			self.users.create_authentication,
			'service',
			self.users.search_authentications,
			'services',
		)

	def test_search_permissions_by_scope(self):
		self.search_by_string_equal(
			self.users.create_permission,
			'scope',
			self.users.search_permissions,
			'scopes',
		)

	def test_search_auto_permissions_by_scope(self):
		self.search_by_string_equal(
			self.users.create_auto_permission,
			'scope',
			self.users.search_auto_permissions,
			'scopes',
		)

	# search by bool
	def test_search_users_by_protection(self):
		def create_user_with_protection(**kwargs):
			user = self.users.create_user()
			if 'protected' in kwargs and kwargs['protected']:
				self.users.protect_user(user.id)
				user = self.users.get_user(user.id)
			return user
		self.search_by_bool(
			create_user_with_protection,
			'protected',
			self.users.search_users,
			'protection',
		)

	def test_search_authentications_by_forbidden(self):
		# using create_unique_authentication to avoid collisions
		self.search_by_bool(
			self.create_unique_authentication,
			'forbidden',
			self.users.search_authentications,
			'forbidden',
		)

	# search by remote origin
	def test_search_sessions_by_remote_origin(self):
		self.search_by_remote_origin(
			self.users.create_session,
			'remote_origin',
			self.users.search_sessions,
			'remote_origins',
		)

	# user status enum
	def test_user_status_enum(self):
		for user_status, name, value in [
				(UserStatus.DEACTIVATED_BY_STAFF, 'DEACTIVATED_BY_STAFF', -2),
				(UserStatus.DEACTIVATED_BY_SELF, 'DEACTIVATED_BY_SELF', -1),
				(UserStatus.AWAITING_ACTIVATION, 'AWAITING_ACTIVATION', 0),
				(UserStatus.ACTIVATED, 'ACTIVATED', 1),
			]:
			self.assertEqual(user_status, UserStatus[name])
			self.assertEqual(user_status, UserStatus(value))

		for invalid_name in [
				'FAKE_USER_STATUS',
				'AWAITING_DEACTIVATION',
				'ACTIVATED_BY_SELF'
			]:
			with self.assertRaises(KeyError):
				UserStatus[invalid_name]

		for invalid_value in [-3, 2, 1000]:
			with self.assertRaises(ValueError):
				UserStatus(invalid_value)

	# scopes, groups, and useragents don't have object models
	# scopes
	def test_create_and_populate_scopes(self):
		self.assertEqual(0, len(self.users.available_scopes))

		self.users.populate_scopes()
		# global scope is always included
		self.assertEqual(1, len(self.users.available_scopes))

		self.assertTrue('scope1' not in self.users.available_scopes)
		self.assertTrue('scope2' not in self.users.available_scopes)

		self.users.create_scope('scope1')
		self.users.create_scope('scope2')
		self.users.populate_scopes()

		self.assertEqual(3, len(self.users.available_scopes))
		self.assertTrue('scope1' in self.users.available_scopes)
		self.assertTrue('scope2' in self.users.available_scopes)
		self.assertTrue('fake_scope' not in self.users.available_scopes)

		self.assert_invalid_string_raises(self.users.create_scope)

	def test_create_duplicate_scope(self):
		self.users.create_scope('scope')
		self.users.populate_scopes()

		self.assertEqual(2, len(self.users.available_scopes))
		self.assertTrue('scope' in self.users.available_scopes)

		self.users.create_scope('scope')
		self.users.populate_scopes()

		self.assertEqual(2, len(self.users.available_scopes))
		self.assertTrue('scope' in self.users.available_scopes)

	def test_delete_scope(self):
		self.users.create_scope('scope1')
		self.users.create_scope('scope2')
		self.users.create_scope('scope3')
		self.users.populate_scopes()

		self.assertEqual(4, len(self.users.available_scopes))
		self.assertTrue('scope1' in self.users.available_scopes)
		self.assertTrue('scope2' in self.users.available_scopes)
		self.assertTrue('scope3' in self.users.available_scopes)

		self.users.delete_scope('scope2')
		self.users.populate_scopes()

		self.assertEqual(3, len(self.users.available_scopes))
		self.assertTrue('scope1' in self.users.available_scopes)
		self.assertTrue('scope2' not in self.users.available_scopes)
		self.assertTrue('scope3' in self.users.available_scopes)

		self.assert_invalid_string_raises(self.users.delete_scope)

	def test_delete_nonexistent_scope(self):
		# attempting to delete a non-existent scope shouldn't raise
		self.users.delete_scope('fake_scope')

	# groups
	def test_create_and_populate_groups(self):
		self.assertEqual(0, len(self.users.available_groups))
		self.assertTrue('group1' not in self.users.available_groups)
		self.assertTrue('group2' not in self.users.available_groups)

		self.assertEqual(0, len(self.users.group_names_to_bits))
		self.assertTrue('group1' not in self.users.group_names_to_bits)
		self.assertTrue('group2' not in self.users.group_names_to_bits)

		self.users.create_group('group1')
		self.users.create_group('group2')
		self.users.populate_groups()

		self.assertEqual(2, len(self.users.available_groups))
		self.assertTrue('group1' in self.users.available_groups)
		self.assertTrue('group2' in self.users.available_groups)
		self.assertTrue('fake_group' not in self.users.available_groups)

		self.assertEqual(2, len(self.users.group_names_to_bits))
		self.assertTrue('group1' in self.users.group_names_to_bits)
		self.assertTrue('group2' in self.users.group_names_to_bits)
		self.assertTrue('fake_group' not in self.users.group_names_to_bits)

		self.assert_invalid_string_raises(self.users.create_group)

	def test_create_duplicate_group(self):
		self.users.create_group('group')
		self.users.populate_groups()

		self.assertEqual(1, len(self.users.available_groups))
		self.assertTrue('group' in self.users.available_groups)

		self.users.create_scope('group')
		self.users.populate_groups()

		self.assertEqual(1, len(self.users.available_groups))
		self.assertTrue('group' in self.users.available_groups)

	def test_create_group_with_invalid_bit(self):
		for invalid_bit in [
				'string',
				['list'],
				{'dict': 'ionary'},
			]:
			with self.assertRaises(Exception):
				self.users.create_group(str(uuid.uuid4()), bit=invalid_bit)

	def test_create_group_with_bit_as_int(self):
		bit_int = 1
		bit_bytes = int(1).to_bytes(2, 'big')
		self.users.create_group('group', bit=bit_int)
		self.users.populate_groups()

		self.assertTrue('group' in self.users.available_groups)
		self.assertTrue('group' in self.users.group_names_to_bits)
		self.assertEqual(
			bit_bytes,
			self.users.group_names_to_bits['group'],
		)

	def test_create_group_with_bit_as_bytes(self):
		bit_bytes = int(1).to_bytes(2, 'big')
		self.users.create_group('group', bit=bit_bytes)
		self.users.populate_groups()

		self.assertTrue('group' in self.users.available_groups)
		self.assertTrue('group' in self.users.group_names_to_bits)
		self.assertEqual(
			bit_bytes,
			self.users.group_names_to_bits['group'],
		)

	def test_create_group_with_bit_collision(self):
		bit_int = 1
		bit_bytes = int(1).to_bytes(2, 'big')
		self.users.create_group('group1', bit=bit_int)
		self.users.populate_groups()

		with self.assertRaises(ValueError):
			self.users.create_group('group2', bit=bit_int)

		with self.assertRaises(ValueError):
			self.users.create_group('group2', bit=bit_bytes)

	def test_delete_group(self):
		self.users.create_group('group1')
		self.users.create_group('group2')
		self.users.populate_groups()

		self.assertEqual(2, len(self.users.available_groups))
		self.assertTrue('group1' in self.users.available_groups)
		self.assertTrue('group2' in self.users.available_groups)

		self.users.create_group('group3')
		self.users.populate_groups()

		self.assertEqual(3, len(self.users.group_names_to_bits))
		self.assertTrue('group1' in self.users.group_names_to_bits)
		self.assertTrue('group2' in self.users.group_names_to_bits)
		self.assertTrue('group3' in self.users.group_names_to_bits)

		self.users.delete_group('group2')
		self.users.populate_groups()

		self.assertEqual(2, len(self.users.available_groups))
		self.assertTrue('group1' in self.users.available_groups)
		self.assertTrue('group2' not in self.users.available_groups)
		self.assertTrue('group3' in self.users.available_groups)

		self.assert_invalid_string_raises(self.users.delete_group)

	def test_create_group_autoassign_bit(self):
		self.users.create_group('group1')
		self.users.create_group('group2')
		self.users.create_group('group3')
		self.users.populate_groups()

		# created groups start at the highest bit made available by
		# self.group_bits_length, and assign to the highest available unused bit
		expected_bit = self.users.group_bits_length * 8
		self.assertEqual(
			expected_bit,
			int.from_bytes(self.users.group_names_to_bits['group1'], 'big'),
		)
		expected_bit = expected_bit >> 1
		self.assertEqual(
			expected_bit,
			int.from_bytes(self.users.group_names_to_bits['group2'], 'big'),
		)
		expected_bit = expected_bit >> 1
		self.assertEqual(
			expected_bit,
			int.from_bytes(self.users.group_names_to_bits['group3'], 'big'),
		)

		# test_group4 should fill the available bit test_group2 was using
		self.users.delete_group('group2')
		self.users.create_group('group4')
		self.users.populate_groups()

		expected_bit = expected_bit << 1
		self.assertEqual(
			expected_bit,
			int.from_bytes(self.users.group_names_to_bits['group4'], 'big'),
		)

	def test_exhaust_available_bits(self):
		# group_bits_length is in bytes, 1 byte allows for 4 groups
		self.users.group_bits_length = 1
		# exhaust all 4 groups
		for i in range(4):
			# random group name to avoid collision
			group_name = str(uuid.uuid4())
			self.users.create_group(group_name)
		# next attempt to create a group should raise
		with self.assertRaises(ValueError):
			self.users.create_group('group')

	def test_group_name_to_bit(self):
		self.users.create_group('group', bit=1)
		self.users.populate_groups()
		bit_bytes = self.users.group_names_to_bits['group']
		self.assertEqual(bit_bytes, self.users.group_name_to_bit('group'))

		# requesting non-existent group should return 0 as bytes
		self.assertEqual(
			int(0).to_bytes(2, 'big'),
			self.users.group_name_to_bit('fake_group'),
		)

	def test_contains_all_bits(self):
		self.assertTrue(self.users.contains_all_bits(3, 1))
		self.assertTrue(self.users.contains_all_bits(3, 2))
		self.assertFalse(self.users.contains_all_bits(3, 5))

		self.assertTrue(
			self.users.contains_all_bits(
				int(3).to_bytes(2, 'big'),
				int(1).to_bytes(2, 'big'),
			)
		)
		self.assertTrue(
			self.users.contains_all_bits(
				int(3).to_bytes(2, 'big'),
				int(2).to_bytes(2, 'big'),
			)
		)
		self.assertFalse(
			self.users.contains_all_bits(
				int(3).to_bytes(2, 'big'),
				int(5).to_bytes(2, 'big'),
			)
		)

	def test_contains_all_bits_invalid(self):
		# contains_all_bits is based on binary operations between ints
		# so should raise for non-int non-bytes-like in either haystack or needle
		invalid_inputs = [
			'string',
			['list'],
			{'dictionary': True},
		]
		for invalid_input in invalid_inputs:
			with self.assertRaises(TypeError):
				self.users.contains_all_bits(invalid_input, 1)

			with self.assertRaises(TypeError):
				self.users.contains_all_bits(1, invalid_input)

			with self.assertRaises(TypeError):
				self.users.contains_all_bits(invalid_input, invalid_input)

	def test_combine_groups(self):
		self.users.create_group('group1', bit=1)
		self.users.create_group('group2', bit=2)
		self.users.populate_groups()

		expected_bytes = int(3).to_bytes(2, 'big')

		# group names
		self.assertEqual(
			expected_bytes,
			self.users.combine_groups(names=['group1', 'group2']),
		)
		# int
		self.assertEqual(
			expected_bytes,
			self.users.combine_groups(bits=[1, 2]),
		)
		# bytes-like
		self.assertEqual(
			expected_bytes,
			self.users.combine_groups(
				bits=[int(1).to_bytes(2, 'big'), int(2).to_bytes(2, 'big')]
			),
		)
		# mixing int and bytes-like is allowed
		self.assertEqual(
			expected_bytes,
			self.users.combine_groups(bits=[1, int(2).to_bytes(2, 'big')]),
		)
		# combine_groups by name uses group_name_to_bit and so returns 0 in
		# bytes for non-existent group names
		self.assertEqual(
			int(1).to_bytes(2, 'big'),
			self.users.combine_groups(names=['group1', 'fake_group']),
		)

	def test_group_names_from_bits_invalid(self):
		self.users.create_group('group')
		self.users.populate_groups()

		# group_names_from_bits uses contains_all_bits
		# so should raise for non-int non-bytes-like
		invalid_inputs = [
			'string',
			['list'],
			{'dictionary': True},
		]
		for invalid_input in invalid_inputs:
			with self.assertRaises(TypeError):
				self.users.group_names_from_bits(invalid_input)

	def test_group_names_from_bits(self):
		self.users.create_group('group1')
		self.users.create_group('group2')
		self.users.create_group('group3')
		self.users.populate_groups()

		group1_and_group2_bits = self.users.combine_groups(
			names=[
				'group1',
				'group2',
			]
		)
		group_names = self.users.group_names_from_bits(group1_and_group2_bits)
		self.assertTrue('group1' in group_names)
		self.assertTrue('group2' in group_names)
		self.assertTrue('group3' not in group_names)

		group1_and_group3_bits = self.users.combine_groups(
			names=[
				'group1',
				'group3',
			]
		)
		group_names = self.users.group_names_from_bits(group1_and_group3_bits)
		self.assertTrue('group1' in group_names)
		self.assertTrue('group2' not in group_names)
		self.assertTrue('group3' in group_names)

	# useragents
	def test_create_and_get_useragent(self):
		useragent_id = self.users.create_useragent('Mozilla')
		self.assertEqual(useragent_id, self.users.get_useragent_id('Mozilla'))
		# attempting to get a non-existent useragent id should return None
		self.assertIsNone(self.users.get_useragent_id('Fake Useragent'))

		self.assert_invalid_string_raises(self.users.create_useragent)

	def test_create_useragent_ignore_duplicate(self):
		# attempting to store an existing useragent will return the existing
		# useragent id without creation
		self.assertEqual(
			self.users.create_useragent('Mozilla'),
			self.users.create_useragent('Mozilla'),
		)

	def test_delete_useragent(self):
		self.users.create_useragent('Mozilla')
		self.assertIsNotNone(self.users.get_useragent_id('Mozilla'))
		self.users.delete_useragent('Mozilla')
		self.assertIsNone(self.users.get_useragent_id('Mozilla'))

		self.assert_invalid_string_raises(self.users.delete_useragent)

	# user
	def test_update_user(self):
		# update_user instantiates a User object so anything that raises in
		# test_user_class_create_get_and_defaults should raise
		user = self.users.create_user()

		# update_user can receive a base64_url string
		properties = {
			'creation_time': 1111111111,
			'touch_time': 1234567890,
			'name': 'test1',
			'display': 'Test1',
			'status': UserStatus.ACTIVATED,
		}
		self.users.update_user(user.id, **properties)
		user = self.users.get_user(user.id_bytes)
		for key, value in properties.items():
			self.assertEqual(getattr(user, key), value)

		# update_user can receive bytes-like
		properties = {
			'creation_time': 2222222222,
			'touch_time':    2345678901,
			'name': 'test2',
			'display': 'Test2',
			'status': UserStatus.DEACTIVATED_BY_SELF,
		}
		self.users.update_user(user.id_bytes, **properties)
		user = self.users.get_user(user.id_bytes)
		for key, value in properties.items():
			self.assertEqual(getattr(user, key), value)

		self.assert_invalid_id_raises(self.users.update_user)

	def test_user_name(self):
		invalid_user_name = 'contains spaces and special characters #$@!'
		with self.assertRaises(ValueError):
			User(name=invalid_user_name)
		# because create_user and update_user both instantiate User objects with
		# the provided properties, they should also raise on invalid names
		with self.assertRaises(ValueError):
			self.users.create_user(name=invalid_user_name)
		user = self.users.create_user()
		with self.assertRaises(ValueError):
			self.users.update_user(user.id, name=invalid_user_name)

		def update_user_name(invalid_user_name):
			user = self.users.create_user()
			self.users.update_user(user.id, name=invalid_user_name)
			
		self.assert_invalid_string_raises(update_user_name)

	def test_allow_duplicate_user_names(self):
		# by default unique user names aren't required
		self.assertFalse(self.users.require_unique_names)

		self.users.create_user(name='test1')
		self.users.create_user(name='test1')

		user = self.users.create_user()
		self.users.update_user(user.id, name='test1')

	def test_require_unique_user_names(self):
		self.users.require_unique_names = True

		user1 = self.users.create_user(name='test1')

		with self.assertRaises(ValueError):
			self.users.create_user(name='test1')

		user2 = self.users.create_user()
		with self.assertRaises(ValueError):
			self.users.update_user(user2.id, name='test1')

		# specifying an unchanged name while updating shouldn't raise
		self.users.update_user(user1.id, touch_time=1234567890, name='test1')

	def test_unique_user_names_as_identifier(self):
		# normally user id is used as identifier
		user1 = self.users.create_user(name='test1')
		self.assertEqual(user1.identifier, user1.id)

		# when unique names are required and a name is present it's used
		self.users.require_unique_names = True
		user2 = self.users.create_user(name='test2')
		self.assertEqual(user2.identifier, 'test2')

		# when unique names are required but name is blank user id is used
		user3 = self.users.create_user()
		self.assertEqual(user3.identifier, user3.id)

	def test_allow_duplicate_user_displays(self):
		# by default unique user displays aren't required
		self.assertFalse(self.users.require_unique_displays)

		self.users.create_user(display='Test1')
		self.users.create_user(display='Test1')

		user = self.users.create_user()
		self.users.update_user(user.id, display='Test1')

	def test_require_unique_user_displays(self):
		self.users.require_unique_displays = True

		user1 = self.users.create_user(display='Test1')

		with self.assertRaises(ValueError):
			self.users.create_user(display='Test1')

		user2 = self.users.create_user()
		with self.assertRaises(ValueError):
			self.users.update_user(user2.id, display='Test1')

		# specifying an unchanged display while updating shouldn't raise
		self.users.update_user(user1.id, touch_time=1234567890, display='Test1')

	def test_user_protection(self):
		user = self.users.create_user()

		self.users.protect_user(user.id_bytes)
		user = self.users.get_user(user.id_bytes)
		self.assertTrue(user.protected)

		self.users.unprotect_user(user.id_bytes)
		user = self.users.get_user(user.id_bytes)
		self.assertFalse(user.protected)

		self.assert_invalid_id_raises(self.users.protect_user)
		self.assert_invalid_id_raises(self.users.unprotect_user)

	def test_search_user_by_status(self):
		user_awaiting = self.users.create_user(
			status=UserStatus.AWAITING_ACTIVATION,
		)
		user_activated = self.users.create_user(
			status=UserStatus.ACTIVATED,
		)
		user_deactivated_by_self = self.users.create_user(
			status=UserStatus.DEACTIVATED_BY_SELF,
		)
		user_deactivated_by_staff = self.users.create_user(
			status=UserStatus.DEACTIVATED_BY_STAFF,
		)

		# single status
		users = self.users.search_users(
			filter={'statuses': UserStatus.AWAITING_ACTIVATION}
		)
		self.assertTrue(user_awaiting in users)
		self.assertTrue(user_activated not in users)
		self.assertTrue(user_deactivated_by_self not in users)
		self.assertTrue(user_deactivated_by_staff not in users)

		users = self.users.search_users(
			filter={'statuses': UserStatus.ACTIVATED}
		)
		self.assertTrue(user_awaiting not in users)
		self.assertTrue(user_activated in users)
		self.assertTrue(user_deactivated_by_self not in users)
		self.assertTrue(user_deactivated_by_staff not in users)

		users = self.users.search_users(
			filter={'statuses': UserStatus.DEACTIVATED_BY_SELF}
		)
		self.assertTrue(user_awaiting not in users)
		self.assertTrue(user_activated not in users)
		self.assertTrue(user_deactivated_by_self in users)
		self.assertTrue(user_deactivated_by_staff not in users)

		users = self.users.search_users(
			filter={'statuses': UserStatus.DEACTIVATED_BY_STAFF}
		)
		self.assertTrue(user_awaiting not in users)
		self.assertTrue(user_activated not in users)
		self.assertTrue(user_deactivated_by_self not in users)
		self.assertTrue(user_deactivated_by_staff in users)

		# multiple statuses
		users = self.users.search_users(
			filter={
				'statuses': [UserStatus.AWAITING_ACTIVATION, UserStatus.ACTIVATED]
			}
		)
		self.assertTrue(user_awaiting in users)
		self.assertTrue(user_activated in users)
		self.assertTrue(user_deactivated_by_self not in users)
		self.assertTrue(user_deactivated_by_staff not in users)

		# a search with only invalid statuses should return no results
		users = self.users.search_users(filter={'statuses': [2, 100]})
		self.assertEqual(0, len(users))
		# a search with at least one valid status should behave normally
		# ignoring any invalid statuses
		users = self.users.search_users(
			filter={'statuses': [UserStatus.AWAITING_ACTIVATION, 2]}
		)
		self.assertTrue(user_awaiting in users)
		self.assertTrue(user_activated not in users)
		self.assertTrue(user_deactivated_by_self not in users)
		self.assertTrue(user_deactivated_by_staff not in users)

	# invites
	def test_redeem_invite(self):
		redeeming_user = self.users.create_user()
		# by user id and user id_bytes
		for id in [redeeming_user.id, redeeming_user.id_bytes]:
			invite1 = self.users.create_invite()
			invite2 = self.users.create_invite()
			# by invite id
			self.users.redeem_invite(invite1.id, id)
			invite = self.users.get_invite(invite1.id)
			self.assertTrue(invite.is_redeemed)
			self.assertEqual(invite.redeemed_by_user_id, redeeming_user.id)
			self.assertEqual(invite.redeemed_by_user_id_bytes, redeeming_user.id_bytes)
			# by invite id bytes
			self.users.redeem_invite(invite2.id_bytes, id)
			invite = self.users.get_invite(invite2.id)
			self.assertTrue(invite.is_redeemed)
			self.assertEqual(invite.redeemed_by_user_id, redeeming_user.id)
			self.assertEqual(invite.redeemed_by_user_id_bytes, redeeming_user.id_bytes)

		self.assert_invalid_id_raises(
			lambda input: self.users.redeem_invite(
				input,
				self.users.create_user().id,
			)
		)
		self.assert_invalid_id_raises(
			lambda input: self.users.redeem_invite(
				self.users.create_invite().id,
				input
			)
		)

	def test_redeem_invite_replay(self):
		# attempting to redeem already redeemed invite should raise
		redeeming_user = self.users.create_user()
		invite = self.users.create_invite()
		self.users.redeem_invite(invite.id, redeeming_user.id)
		with self.assertRaises(ValueError): # Invite already redeemed
			self.users.redeem_invite(invite.id, redeeming_user.id)

	def test_redeem_invite_nonexistent(self):
		# invalid invite id or non-existent invite should raise
		redeeming_user = self.users.create_user()
		with self.assertRaises(ValueError): # Invite not found
			self.users.redeem_invite(uuid.uuid4().bytes, redeeming_user.id)

	def test_delete_user_created_invites(self):
		user1 = self.users.create_user()
		user2 = self.users.create_user()

		invite1 = self.users.create_invite(created_by_user_id=user1.id)
		invite2 = self.users.create_invite(created_by_user_id=user2.id)

		self.users.delete_user_created_invites(user1.id)
		self.assertIsNone(self.users.get_invite(invite1.id))
		self.assertIsNotNone(self.users.get_invite(invite2.id))

	def test_delete_user_created_invites_preserving_redeemed(self):
		user1 = self.users.create_user()
		user2 = self.users.create_user()

		invite1 = self.users.create_invite(created_by_user_id=user1.id)
		invite2 = self.users.create_invite(created_by_user_id=user1.id)

		self.users.redeem_invite(invite1.id, user2.id)

		self.users.delete_user_created_invites(user1.id, preserve_redeemed=True)
		self.assertIsNotNone(self.users.get_invite(invite1.id))
		self.assertIsNone(self.users.get_invite(invite2.id))

	# sessions
	def test_touch_session(self):
		session = self.users.create_session(touch_time=0)
		# by id
		self.users.touch_session(session.id)
		self.assertNotEqual(
			session.touch_time,
			self.users.get_session(session.id).touch_time,
		)
		# by id_bytes
		self.users.touch_session(session.id_bytes)
		self.assertNotEqual(
			session.touch_time,
			self.users.get_session(session.id).touch_time,
		)

		self.assert_invalid_id_raises(self.users.touch_session)

	def test_touch_session_with_time(self):
		session = self.users.create_session(touch_time=0)
		# by id
		self.users.touch_session(session.id, touch_time=1)
		self.assertEqual(1, self.users.get_session(session.id).touch_time)
		# by id_bytes
		self.users.touch_session(session.id_bytes, touch_time=2)
		self.assertEqual(2, self.users.get_session(session.id).touch_time)

		self.assert_invalid_id_raises(
			lambda input: self.users.touch_session(input, touch_time=1234567890)
		)
		self.assert_invalid_timestamp_raises(
			lambda input: self.users.touch_session(
				self.users.create_session().id,
				touch_time=input,
			)
		)

	def test_close_session(self):
		session1 = self.users.create_session()
		session2 = self.users.create_session()
		# by id
		self.users.close_session(session1.id)
		self.assertNotEqual(
			session1.close_time,
			self.users.get_session(session1.id).close_time,
		)
		# by id_bytes
		self.users.close_session(session2.id_bytes)
		self.assertNotEqual(
			session2.close_time,
			self.users.get_session(session2.id).close_time,
		)

		self.assert_invalid_id_raises(self.users.close_session)

	def test_close_session_with_time(self):
		session1 = self.users.create_session()
		session2 = self.users.create_session()
		# by id
		self.users.close_session(session1.id, close_time=1)
		self.assertEqual(1, self.users.get_session(session1.id).close_time)
		# by id_bytes
		self.users.close_session(session2.id_bytes, close_time=2)
		self.assertEqual(2, self.users.get_session(session2.id).close_time)

		self.assert_invalid_id_raises(
			lambda input: self.users.close_session(input, close_time=1234567890)
		)
		self.assert_invalid_timestamp_raises(
			lambda input: self.users.close_session(
				self.users.create_session().id,
				close_time=input,
			)
		)

	def test_close_nonexistent_session(self):
		with self.assertRaises(ValueError):
			self.users.close_session(uuid.uuid4().bytes)

	def test_close_already_closed_session(self):
		session = self.users.create_session()
		self.users.close_session(session.id)
		with self.assertRaises(Exception):
			self.users.close_session(session.id)

	def test_close_user_sessions(self):
		# by id
		user = self.users.create_user()
		session1 = self.users.create_session(user_id=user.id)
		session2 = self.users.create_session(user_id=user.id)
		self.assertEqual(0, session1.close_time)
		self.assertEqual(0, session2.close_time)

		self.users.close_user_sessions(user.id)

		session1 = self.users.get_session(session1.id)
		session2 = self.users.get_session(session2.id)
		self.assertNotEqual(0, session1.close_time)
		self.assertNotEqual(0, session2.close_time)

		# test by id_bytes
		session1 = self.users.create_session(user_id=user.id)
		session2 = self.users.create_session(user_id=user.id)
		self.assertEqual(0, session1.close_time)
		self.assertEqual(0, session2.close_time)

		self.users.close_user_sessions(user.id_bytes)

		session1 = self.users.get_session(session1.id)
		session2 = self.users.get_session(session2.id)
		self.assertNotEqual(0, session1.close_time)
		self.assertNotEqual(0, session2.close_time)

		self.assert_invalid_id_raises(self.users.close_user_sessions)

	def test_close_user_sessions_with_time(self):
		user = self.users.create_user()
		session1 = self.users.create_session(user_id=user.id)
		session2 = self.users.create_session(user_id=user.id)
		self.assertEqual(0, session1.close_time)
		self.assertEqual(0, session2.close_time)

		self.users.close_user_sessions(user.id, close_time=1234567890)

		session1 = self.users.get_session(session1.id)
		session2 = self.users.get_session(session2.id)
		self.assertEqual(1234567890, session1.close_time)
		self.assertEqual(1234567890, session2.close_time)

		self.assert_invalid_timestamp_raises(
			lambda input: self.users.close_user_sessions(
				self.users.create_user().id,
				input,
			)
		)

	def test_close_only_unclosed_user_sessions(self):
		user = self.users.create_user()
		session1 = self.users.create_session(user_id=user.id)
		self.users.close_user_sessions(user.id, close_time=1)
		self.assertEqual(1, self.users.get_session(session1.id).close_time)
		session2 = self.users.create_session(user_id=user.id)
		self.users.close_user_sessions(user.id, close_time=2)
		self.assertEqual(2, self.users.get_session(session2.id).close_time)
		# first closed session close time should be unaffected
		self.assertEqual(1, self.users.get_session(session1.id).close_time)

	def test_prune_sessions_all(self):
		session1 = self.users.create_session()
		session2 = self.users.create_session(close_time=1)
		session3 = self.users.create_session(close_time=2)
		session4 = self.users.create_session(close_time=3)

		self.assertIsNotNone(self.users.get_session(session1.id))
		self.assertIsNotNone(self.users.get_session(session2.id))
		self.assertIsNotNone(self.users.get_session(session3.id))
		self.assertIsNotNone(self.users.get_session(session4.id))

		self.users.prune_sessions()

		# unclosed sessions aren't pruned
		self.assertIsNotNone(self.users.get_session(session1.id))

		self.assertIsNone(self.users.get_session(session2.id))
		self.assertIsNone(self.users.get_session(session3.id))
		self.assertIsNone(self.users.get_session(session4.id))

	def test_prune_sessions_closed_before(self):
		session1 = self.users.create_session()
		session2 = self.users.create_session(close_time=1)
		session3 = self.users.create_session(close_time=2)
		session4 = self.users.create_session(close_time=3)

		self.assertIsNotNone(self.users.get_session(session1.id))
		self.assertIsNotNone(self.users.get_session(session2.id))
		self.assertIsNotNone(self.users.get_session(session3.id))
		self.assertIsNotNone(self.users.get_session(session4.id))

		self.users.prune_sessions(closed_before=3)

		# unclosed sessions aren't pruned
		self.assertIsNotNone(self.users.get_session(session1.id))

		self.assertIsNone(self.users.get_session(session2.id))
		self.assertIsNone(self.users.get_session(session3.id))
		self.assertIsNotNone(self.users.get_session(session4.id))

	def test_delete_user_sessions(self):
		user = self.users.create_user()

		# by id
		session1 = self.users.create_session(user_id=user.id)
		session2 = self.users.create_session(user_id=user.id)
		self.assertIsNotNone(self.users.get_session(session1.id))
		self.assertIsNotNone(self.users.get_session(session2.id))

		self.users.delete_user_sessions(user.id)

		self.assertIsNone(self.users.get_session(session1.id))
		self.assertIsNone(self.users.get_session(session2.id))

		# by id_bytes
		session1 = self.users.create_session(user_id=user.id)
		session2 = self.users.create_session(user_id=user.id)
		self.assertIsNotNone(self.users.get_session(session1.id))
		self.assertIsNotNone(self.users.get_session(session2.id))

		self.users.delete_user_sessions(user.id_bytes)

		self.assertIsNone(self.users.get_session(session1.id))
		self.assertIsNone(self.users.get_session(session2.id))

		self.assert_invalid_id_raises(self.users.delete_user_sessions)

	#TODO direct sessions useragents search tests
	def test_search_sessions_by_useragent(self):
		useragent1 = 'Mozilla'
		useragent2 = 'Bot'

		session1 = self.users.create_session(useragent=useragent1)
		session2 = self.users.create_session(useragent=useragent1)
		session3 = self.users.create_session(useragent=useragent2)

		sessions = self.users.search_sessions(
			filter={'useragents': useragent1},
		)
		self.assertTrue(session1 in sessions)
		self.assertTrue(session2 in sessions)
		self.assertTrue(session3 not in sessions)

		sessions = self.users.search_sessions(
			filter={'useragents': useragent2},
		)
		self.assertTrue(session1 not in sessions)
		self.assertTrue(session2 not in sessions)
		self.assertTrue(session3 in sessions)

		sessions = self.users.search_sessions(
			filter={'useragents': [useragent1, useragent2]},
		)
		self.assertTrue(session1 in sessions)
		self.assertTrue(session2 in sessions)
		self.assertTrue(session3 in sessions)

		# filters with all invalid values should return none
		# filters with at least one valid value should behave normally
		# ignoring any invalid values
		# but since filters are cast to string before the query they should
		# always be valid
		pass

	# authentications
	def test_forbidden_authentication(self):
		authentication = self.users.create_authentication()

		self.users.forbid_authentication(authentication.id)
		authentication = self.users.get_authentication(authentication.id)
		self.assertTrue(authentication.forbidden)

		self.users.unforbid_authentication(authentication.id)
		authentication = self.users.get_authentication(authentication.id)
		self.assertFalse(authentication.forbidden)

		self.assert_invalid_id_raises(self.users.forbid_authentication)
		self.assert_invalid_id_raises(self.users.unforbid_authentication)

	def test_forbidden_authentication_collision(self):
		# attempting to create authentications with a service/value pair
		# that are marked forbidden should raise
		user1 = self.users.create_user()
		user2 = self.users.create_user()
		authentication = self.users.create_authentication(
			user_id=user1.id,
			service='google',
			value='some_google_id',
			forbidden=True,
		)
		with self.assertRaises(ValueError):
			self.users.create_authentication(
				user_id=user2.id,
				service='google',
				value='some_google_id',
			)

	def test_authentication_collision_single_service_per_user(self):
		# currently each user can only have one authentication per service
		# so attempting to create authentications with duplicate
		# user_id/service pairs should raise regardless of value
		user_id = uuid.uuid4().bytes
		authentication = self.users.create_authentication(
			user_id=user_id,
			service='google',
			value='some_google_id',
		)
		with self.assertRaises(Exception):
			self.users.create_authentication(
				user_id=user_id,
				service='google',
				value='some_other_google_id',
			)

	def test_authentication_collision_in_use(self):
		# attempting to create authentications with a service/value pair
		# that are already tied to a user should raise
		user1_id = uuid.uuid4().bytes
		user2_id = uuid.uuid4().bytes
		authentication = self.users.create_authentication(
			user_id=user1_id,
			service='google',
			value='some_google_id',
		)
		with self.assertRaises(Exception):
			self.users.create_authentication(
				user_id=user2_id,
				service='google',
				value='some_google_id',
			)

	def test_get_authentication_value(self):
		authentication = self.create_unique_authentication()
		value = self.users.get_authentication_value(
			authentication.user_id,
			authentication.service,
		)
		self.assertEqual(authentication.value, value)

		self.assert_invalid_string_raises(
			lambda input: self.users.get_authentication_value(
				authentication.user_id,
				input,
			)
		)
		self.assert_invalid_id_returns_none(
			lambda input: self.users.get_authentication_value(
				input,
				authentication.service,
			)
		)

	def test_get_authentication_user_id(self):
		authentication = self.create_unique_authentication()
		user_id = self.users.get_authentication_user_id(
			authentication.service,
			authentication.value,
		)
		self.assertEqual(authentication.user_id, user_id)

		self.assert_invalid_string_raises(
			lambda input: self.users.get_authentication_user_id(
				input,
				authentication.value,
			)
		)
		self.assert_invalid_string_raises(
			lambda input: self.users.get_authentication_user_id(
				authentication.service,
				input,
			)
		)

	def test_get_user_authentications(self):
		user1 = self.users.create_user()
		authentication1 = self.users.create_authentication(
			user_id=user1.id,
			service='google',
			value='some_google_id',
		)
		authentication2 = self.users.create_authentication(
			user_id=user1.id,
			service='twitter',
			value='some_twitter_id',
		)

		user2 = self.users.create_user()
		authentication3 = self.users.create_authentication(
			user_id=user2.id,
			service='google',
			value='some_other_google_id',
		)

		user1_authentications = self.users.get_user_authentications(user1.id)
		self.assertTrue(
			authentication1 in user1_authentications
			and authentication2 in user1_authentications
			and authentication3 not in user1_authentications
		)

		user2_authentications = self.users.get_user_authentications(user2.id)
		self.assertTrue(
			authentication1 not in user2_authentications
			and authentication2 not in user2_authentications
			and authentication3 in user2_authentications
		)

		# invalid user id should return empty dict
		for invalid_id in [
				'string'
			]:
			with self.assertRaises(Exception):
				self.assertEqual(
					{},
					self.users.get_user_authentications(invalid_id),
				)

	def test_populate_user_authentications(self):
		user1 = self.users.create_user()
		user2 = self.users.create_user()
		authentication1 = self.users.create_authentication(
			user_id=user1.id,
			service='google',
			value='some_google_id',
		)
		authentication2 = self.users.create_authentication(
			user_id=user1.id,
			service='twitter',
			value='some_twitter_id',
		)
		authentication3 = self.users.create_authentication(
			user_id=user2.id,
			service='google',
			value='some_other_google_id',
		)
		authentication4 = self.users.create_authentication(
			user_id=user2.id,
			service='discord',
			value='some_discord_id',
		)

		self.users.populate_user_authentications(user1)
		self.assertEqual(2, len(user1.authentications))
		self.assertTrue(
			'google' in user1.authentications
			and 'twitter' in user1.authentications
			and 'discord' not in user1.authentications
		)
		self.assertTrue(
			compare_base_attributes(
				authentication1,
				user1.authentications['google'],
			)
		)
		self.assertTrue(
			compare_base_attributes(
				authentication2,
				user1.authentications['twitter'],
			)
		)

		self.users.populate_user_authentications(user2)
		self.assertEqual(2, len(user2.authentications))
		self.assertTrue(
			'google' in user2.authentications
			and 'twitter' not in user2.authentications
			and 'discord' in user2.authentications
		)
		self.assertTrue(
			compare_base_attributes(
				authentication3,
				user2.authentications['google'],
			)
		)
		self.assertTrue(
			compare_base_attributes(
				authentication4,
				user2.authentications['discord'],
			)
		)

		self.assert_non_user_raises(self.users.populate_user_authentications)

	def test_delete_user_authentication_by_service(self):
		user = self.users.create_user()
		authentication = self.users.create_authentication(
			user_id=user.id,
			service='google',
			value='some_google_id',
		)
		self.assertIsNotNone(self.users.get_authentication(authentication.id))
		self.users.delete_user_authentications(
			authentication.user_id,
			service=authentication.service,
		)
		self.assertIsNone(self.users.get_authentication(authentication.id))

		self.assert_invalid_id_raises(
			lambda input: self.users.delete_user_authentications(
				input,
				service=authentication.service,
			)
		)
		self.assert_invalid_string_raises(
			lambda input: self.users.delete_user_authentications(
				authentication.user_id,
				service=input,
			)
		)

	def test_delete_all_user_authentications(self):
		user = self.users.create_user()
		authentication1 = self.users.create_authentication(
			user_id=user.id,
			service='google',
			value='some_google_id',
		)
		authentication2 = self.users.create_authentication(
			user_id=user.id,
			service='twitter',
			value='some_twitter_id',
		)
		self.assertIsNotNone(self.users.get_authentication(authentication1.id))
		self.assertIsNotNone(self.users.get_authentication(authentication2.id))
		self.users.delete_user_authentications(user.id)
		self.assertIsNone(self.users.get_authentication(authentication1.id))
		self.assertIsNone(self.users.get_authentication(authentication2.id))

	def test_delete_service_authentication_by_value(self):
		user = self.users.create_user()
		authentication = self.users.create_authentication(
			user_id=user.id,
			service='google',
			value='some_google_id',
		)
		self.assertIsNotNone(self.users.get_authentication(authentication.id))
		self.users.delete_service_authentication_by_value(
			authentication.service,
			authentication.value,
		)
		self.assertIsNone(self.users.get_authentication(authentication.id))

	# search by group bits
	def test_search_permissions_by_group_bits(self):
		self.search_by_group_bits(
			self.create_unique_permission,
			self.users.search_permissions,
		)

	def test_search_auto_permissions_by_group_bits(self):
		self.search_by_group_bits(
			self.users.create_auto_permission,
			self.users.search_auto_permissions,
		)

	# permissions
	def test_permission_collision(self):
		# attempting to create permissions with duplicate user_id/scope
		# pairs should replace the existing permission by deletion
		user = self.users.create_user()
		permission1 = self.users.create_permission(
			user_id=user.id,
			scope='scope',
		)
		permission2 = self.users.create_permission(
			user_id=user.id,
			scope='scope',
		)
		self.assertIsNone(self.users.get_permission(permission1.id))

	def test_get_user_permission(self):
		user1 = self.users.create_user()
		user2 = self.users.create_user()
		permission1 = self.users.create_permission(
			user_id=user1.id,
			scope='scope1',
		)
		permission2 = self.users.create_permission(
			user_id=user1.id,
			scope='scope2',
		)
		permission3 = self.users.create_permission(user_id=user2.id)

		self.assertTrue(
			compare_base_attributes(
				permission1,
				self.users.get_user_permission(user1.id, 'scope1'),
			)
		)
		self.assertTrue(
			compare_base_attributes(
				permission2,
				self.users.get_user_permission(user1.id, 'scope2'),
			)
		)

		self.assert_invalid_id_raises(
			lambda input: self.users.get_user_permission(
				input,
				'scope1',
			)
		)
		self.assert_invalid_string_raises(
			lambda input: self.users.get_user_permission(
				user1.id,
				input,
			)
		)

	def test_get_user_permissions(self):
		user1 = self.users.create_user()
		user2 = self.users.create_user()
		permission1 = self.users.create_permission(
			user_id=user1.id,
			scope='scope1',
		)
		permission2 = self.users.create_permission(
			user_id=user1.id,
			scope='scope2',
		)
		permission3 = self.users.create_permission(user_id=user2.id)

		permissions = self.users.get_user_permissions(user1.id)
		self.assertTrue(permission1 in permissions)
		self.assertTrue(permission2 in permissions)
		self.assertTrue(permission3 not in permissions)

		permissions = self.users.get_user_permissions(user2.id)
		self.assertTrue(permission1 not in permissions)
		self.assertTrue(permission2 not in permissions)
		self.assertTrue(permission3 in permissions)

		self.assert_invalid_id_raises(self.users.get_user_permission)

	def test_populate_user_permissions(self):
		self.users.create_scope('scope')
		self.users.populate_scopes()

		self.users.create_group('group1')
		self.users.create_group('group2')
		self.users.populate_groups()

		user1 = self.users.create_user()
		user2 = self.users.create_user()

		permission1 = self.users.create_permission(
			user_id=user1.id,
			scope='scope',
			group_bits=self.users.combine_groups(names=['group1', 'group2']),
		)
		permission2 = self.users.create_permission(
			user_id=user2.id,
			scope='scope',
			group_bits=self.users.group_name_to_bit('group2'),
		)

		self.users.populate_user_permissions(user1)
		self.assertTrue('scope' in user1.permissions)
		self.assertTrue(
			compare_base_attributes(
				permission1,
				user1.permissions['scope'],
			)
		)

		self.users.populate_user_permissions(user2)
		self.assertTrue('scope' in user2.permissions)
		self.assertTrue(
			compare_base_attributes(
				permission2,
				user2.permissions['scope'],
			)
		)

		self.assert_non_user_raises(self.users.populate_user_permissions)

	def test_user_has_permission_invalid(self):
		self.users.create_scope('scope')
		self.users.populate_scopes()

		self.users.create_group('group')
		self.users.populate_groups()
		
		user = self.users.create_user()

		# scope only checks if the provided string exists in the user's
		# permissions dictionary so invalid strings should return false
		for invalid_input in [
				1,
				['list'],
				{'dict': 'ionary'},
			]:
			self.assertFalse(
				user.has_permission(scope=invalid_input, group_bits=0)
			)

		# providing non-int, non-bytes-like, or list of either to group_bits
		# should return false
		for invalid_input in [
				'string',
				['list'],
				{'dict': 'ionary'},
			]:
			self.assertFalse(
				user.has_permission(
					scope='scope',
					group_bits=invalid_input,
				)
			)

		# group_names only checks if the provided strings exist in the user's
		# matching permission scope group_names list, so invalid strings should
		# return false
		for invalid_input in [
				1,
				['list'],
				{'dict': 'ionary'},
			]:
			self.assertFalse(
				user.has_permission(
					scope='scope',
					group_names=invalid_input,
				)
			)

	def test_user_has_permission(self):
		self.users.create_scope('scope')
		self.users.populate_scopes()

		self.users.create_group('group')
		self.users.populate_groups()

		user = self.users.create_user()

		# by group bits
		self.assertFalse(
			user.has_permission(
				scope='scope',
				group_bits=self.users.group_name_to_bit('group'),
			)
		)
		# by group names
		self.assertFalse(
			user.has_permission(
				scope='scope',
				group_names='group',
			)
		)

		permission = self.users.create_permission(
			user_id=user.id,
			scope='scope',
			group_bits=self.users.group_name_to_bit('group'),
		)
		self.users.populate_user_permissions(user)

		# by group bits
		self.assertTrue(
			user.has_permission(
				scope='scope',
				group_bits=self.users.group_name_to_bit('group'),
			)
		)
		# by group names
		self.assertTrue(
			user.has_permission(
				scope='scope',
				group_names='group',
			)
		)

	def test_user_has_permission_with_global(self):
		self.users.create_scope('scope')
		self.users.populate_scopes()

		self.users.create_group('group')
		self.users.populate_groups()

		user = self.users.create_user()

		# by group bits
		self.assertFalse(
			user.has_permission(
				scope='scope',
				group_bits=self.users.group_name_to_bit('group'),
			)
		)
		# by group names
		self.assertFalse(
			user.has_permission(
				scope='scope',
				group_names='group',
			)
		)

		permission = self.users.create_permission(
			user_id=user.id,
			scope='',
			group_bits=self.users.group_name_to_bit('group'),
		)
		self.users.populate_user_permissions(user)

		# has_permission for scoped permission returns true if user has global
		# of that permission
		# by bits
		self.assertTrue(
			user.has_permission(
				scope='scope',
				group_bits=self.users.group_name_to_bit('group'),
			)
		)
		# by group names
		self.assertTrue(
			user.has_permission(
				scope='scope',
				group_names='group',
			)
		)

	def test_delete_user_permissions_invalid(self):
		self.assert_invalid_id_raises(self.users.delete_user_permissions)

	def test_delete_user_permissions_with_protection(self):
		user1 = self.users.create_user()
		user2 = self.users.create_user()
		self.users.protect_user(user1.id)
		self.users.protect_user(user2.id)
		permission1 = self.users.create_permission(
			user_id=user1.id,
			scope='scope1',
		)
		permission2 = self.users.create_permission(
			user_id=user2.id,
			scope='scope2',
		)
		self.assertIsNotNone(self.users.get_permission(permission1.id))
		self.assertIsNotNone(self.users.get_permission(permission2.id))
		# preserve_protected defaults to true, permissions of protected users
		# are unaffected even when directly specified
		self.users.delete_permissions(user_ids=user1.id)
		self.assertIsNotNone(self.users.get_permission(permission1.id))
		self.users.delete_permissions(scope='scope2')
		self.assertIsNotNone(self.users.get_permission(permission2.id))
		# specifying preserve_protected false will ignore protection status when
		# deleting permissions
		self.users.delete_permissions(user_ids=user1.id, preserve_protected=False)
		self.assertIsNone(self.users.get_permission(permission1.id))
		self.users.delete_permissions(scope='scope2', preserve_protected=False)
		self.assertIsNone(self.users.get_permission(permission2.id))

	def test_delete_user_permissions_by_user_ids(self):
		user1 = self.users.create_user()
		user2 = self.users.create_user()
		permission1 = self.users.create_permission(
			user_id=user1.id,
			scope='scope',
		)
		permission2 = self.users.create_permission(
			user_id=user2.id,
			scope='scope',
		)
		self.assertIsNotNone(self.users.get_permission(permission1.id))
		self.assertIsNotNone(self.users.get_permission(permission2.id))
		self.users.delete_permissions(user_ids=user1.id)
		self.assertIsNone(self.users.get_permission(permission1.id))
		self.assertIsNotNone(self.users.get_permission(permission2.id))

	def test_delete_multiple_user_permissions_by_user_ids(self):
		user1 = self.users.create_user()
		user2 = self.users.create_user()
		permission1 = self.users.create_permission(
			user_id=user1.id,
			scope='scope',
		)
		permission2 = self.users.create_permission(
			user_id=user2.id,
			scope='scope',
		)
		self.assertIsNotNone(self.users.get_permission(permission1.id))
		self.assertIsNotNone(self.users.get_permission(permission2.id))
		self.users.delete_permissions(user_ids=[user1.id, user2.id])
		self.assertIsNone(self.users.get_permission(permission1.id))
		self.assertIsNone(self.users.get_permission(permission2.id))

	def test_delete_user_permissions_by_scope(self):
		user1 = self.users.create_user()
		permission1 = self.users.create_permission(
			user_id=user1.id,
			scope='scope1',
		)
		permission2 = self.users.create_permission(
			user_id=user1.id,
			scope='scope2',
		)
		self.assertIsNotNone(self.users.get_permission(permission1.id))
		self.assertIsNotNone(self.users.get_permission(permission2.id))
		self.users.delete_permissions(scope='scope1')
		self.assertIsNone(self.users.get_permission(permission1.id))
		self.assertIsNotNone(self.users.get_permission(permission2.id))

	def test_delete_multiple_user_permissions_by_scope(self):
		user1 = self.users.create_user()
		user2 = self.users.create_user()
		permission1 = self.users.create_permission(
			user_id=user1.id,
			scope='scope',
		)
		permission2 = self.users.create_permission(
			user_id=user2.id,
			scope='scope',
		)
		self.assertIsNotNone(self.users.get_permission(permission1.id))
		self.assertIsNotNone(self.users.get_permission(permission2.id))
		self.users.delete_permissions(scope='scope')
		self.assertIsNone(self.users.get_permission(permission1.id))
		self.assertIsNone(self.users.get_permission(permission2.id))

	def test_delete_all_user_permissions(self):
		user = self.users.create_user()
		self.users.create_permission(
			user_id=user.id,
			scope='scope1',
		)
		self.users.create_permission(
			user_id=user.id,
			scope='scope2',
		)
		self.users.create_permission(
			user_id=user.id,
			scope='scope3',
		)
		self.assertEqual(3, len(self.users.get_user_permissions(user.id)))
		self.users.delete_user_permissions(user.id)
		self.assertEqual(0, len(self.users.get_user_permissions(user.id)))

		self.assert_invalid_id_raises(self.users.delete_user_permissions)

	# auto permissions
	def test_sync_auto_permissions_invalid(self):
		# since sync_auto_permissions uses search_auto_permissions then invalid
		# ids are consumed by the statement helper
		# if only invalid ids are provided then no results are affected
		# if at least one valid id is provided then the sync behaves normally
		#TODO write some kind of test for this?
		pass

	def test_sync_auto_permissions_by_ids(self):
		self.users.create_scope('scope')
		self.users.populate_scopes()

		self.users.create_group('group')
		self.users.populate_groups()

		user1 = self.users.create_user()
		user2 = self.users.create_user()
		self.users.create_permission(
			user_id=user1.id,
			scope='scope',
			group_bits=self.users.group_name_to_bit('group'),
		)
		self.users.create_permission(
			user_id=user2.id,
			scope='scope',
			group_bits=self.users.group_name_to_bit('group'),
		)
		self.users.populate_user_permissions(user1)
		self.users.populate_user_permissions(user2)

		self.assertTrue(user1.has_permission(scope='scope', group_names='group'))
		self.assertTrue(user2.has_permission(scope='scope', group_names='group'))

		auto_permission1 = self.users.create_auto_permission(
			user_id=user1.id,
			scope='scope',
			group_bits=self.users.group_name_to_bit('group'),
			valid_from_time=0,
			valid_until_time=(time.time() - 1000),
		)

		# user2 permissions not revoked if they're not included in the sync
		self.users.sync_auto_permissions(ids=auto_permission1.id)
		self.users.populate_user_permissions(user1)
		self.users.populate_user_permissions(user2)
		self.assertFalse(
			user1.has_permission(scope='scope', group_names='group')
		)
		self.assertTrue(user2.has_permission(scope='scope', group_names='group'))

		auto_permission2 = self.users.create_auto_permission(
			user_id=user1.id,
			scope='scope',
			group_bits=self.users.group_name_to_bit('group'),
			valid_from_time=(time.time() - 1000),
			valid_until_time=(time.time() + 1000),
		)

		# user2 permissions still not revoked if they're not included in the sync
		self.users.sync_auto_permissions(
			ids=[auto_permission1.id, auto_permission2.id],
		)
		self.users.populate_user_permissions(user1)
		self.users.populate_user_permissions(user2)
		self.assertTrue(user1.has_permission(scope='scope', group_names='group'))
		self.assertTrue(user2.has_permission(scope='scope', group_names='group'))

	def test_sync_auto_permissions_by_user_ids(self):
		self.users.create_scope('scope')
		self.users.populate_scopes()

		self.users.create_group('group')
		self.users.populate_groups()

		user1 = self.users.create_user()
		user2 = self.users.create_user()
		self.users.create_permission(
			user_id=user1.id,
			scope='scope',
			group_bits=self.users.group_name_to_bit('group'),
		)
		self.users.create_permission(
			user_id=user2.id,
			scope='scope',
			group_bits=self.users.group_name_to_bit('group'),
		)
		self.users.populate_user_permissions(user1)
		self.users.populate_user_permissions(user2)

		self.assertTrue(user1.has_permission(scope='scope', group_names='group'))
		self.assertTrue(user2.has_permission(scope='scope', group_names='group'))

		# user2 permissions not revoked if they're not included in the sync
		self.users.sync_auto_permissions(user_ids=user1.id)
		self.users.populate_user_permissions(user1)
		self.users.populate_user_permissions(user2)
		self.assertFalse(
			user1.has_permission(scope='scope', group_names='group')
		)
		self.assertTrue(user2.has_permission(scope='scope', group_names='group'))

		self.users.create_auto_permission(
			user_id=user1.id,
			scope='scope',
			group_bits=self.users.group_name_to_bit('group'),
			valid_from_time=(time.time() - 1000),
			valid_until_time=(time.time() + 1000),
		)

		# user2 permissions still not revoked if they're not included in the sync
		self.users.sync_auto_permissions(user_ids=user1.id)
		self.users.populate_user_permissions(user1)
		self.users.populate_user_permissions(user2)
		self.assertTrue(user1.has_permission(scope='scope', group_names='group'))
		self.assertTrue(user2.has_permission(scope='scope', group_names='group'))

	def test_sync_all_auto_permissions(self):
		self.users.create_scope('scope')
		self.users.populate_scopes()

		self.users.create_group('group')
		self.users.populate_groups()

		user1 = self.users.create_user()
		user2 = self.users.create_user()
		permission1 = self.users.create_permission(
			user_id=user1.id,
			scope='scope',
			group_bits=self.users.group_name_to_bit('group'),
		)
		permission2 = self.users.create_permission(
			user_id=user2.id,
			scope='scope',
			group_bits=self.users.group_name_to_bit('group'),
		)
		self.users.populate_user_permissions(user1)
		self.users.populate_user_permissions(user2)
		self.assertTrue(
			user1.has_permission(scope='scope', group_names='group')
		)
		self.assertTrue(
			user2.has_permission(scope='scope', group_names='group')
		)

		# all permissions are revoked from sync all
		self.users.sync_auto_permissions()
		self.users.populate_user_permissions(user1)
		self.users.populate_user_permissions(user2)
		self.assertFalse(
			user1.has_permission(scope='scope', group_names='group')
		)
		self.assertFalse(
			user2.has_permission(scope='scope', group_names='group'),
		)

		self.users.create_auto_permission(
			user_id=user1.id,
			scope='scope',
			group_bits=self.users.group_name_to_bit('group'),
			valid_from_time=(time.time() - 1000),
			valid_until_time=(time.time() + 1000),
		)
		self.users.sync_auto_permissions()
		self.users.populate_user_permissions(user1)
		self.users.populate_user_permissions(user2)
		self.assertTrue(
			user1.has_permission(scope='scope', group_names='group')
			and not user2.has_permission(
				scope='scope',
				group_names='group',
			)
		)

	# anonymization
	def test_anonymize_user(self):
		user = self.users.create_user(name='test', display='Test')
		self.users.create_invite(created_by_user_id=user.id)
		self.users.create_invite(redeemed_by_user_id=user.id)
		self.users.create_session(user_id=user.id)
		self.users.create_authentication(user_id=user.id)
		self.users.create_permission(user_id=user.id)
		self.users.create_auto_permission(user_id=user.id)

		count_methods_filter_fields = [
			(self.users.count_invites, 'created_by_user_ids'),
			(self.users.count_invites, 'redeemed_by_user_ids'),
			(self.users.count_sessions, 'user_ids'),
			(self.users.count_authentications, 'user_ids'),
			(self.users.count_permissions, 'user_ids'),
			(self.users.count_auto_permissions, 'user_ids'),
		]
		self.assertIsNotNone(self.users.get_user(user.id))
		for count, filter_field in count_methods_filter_fields:
			self.assertEqual(1, count(filter={filter_field: user.id}))

		new_id_bytes = self.users.anonymize_user(user.id)

		self.assertIsNone(self.users.get_user(user.id))
		for count, filter_field in count_methods_filter_fields:
			self.assertEqual(0, count(filter={filter_field: user.id}))

		# assert user and related data still exist, but with the new id
		self.assertIsNotNone(self.users.get_user(new_id_bytes))
		for count, filter_field in count_methods_filter_fields:
			self.assertEqual(1, count(filter={filter_field: new_id_bytes}))

	def test_anonymize_session_origins(self):
		origin1 = '1.2.3.4'
		expected_anonymized_origin1 = '1.2.0.0'
		session1 = self.users.create_session(remote_origin=origin1)

		origin2 = '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
		expected_anonymized_origin2 = '2001:0db8:85a3:0000:0000:0000:0000:0000'
		session2 = self.users.create_session(remote_origin=origin2)

		sessions = self.users.search_sessions()
		self.users.anonymize_session_origins(sessions)

		anonymized_session1 = self.users.get_session(session1.id)
		anonymized_session2 = self.users.get_session(session2.id)

		self.assertEqual(
			expected_anonymized_origin1,
			anonymized_session1.remote_origin.exploded,
		)
		self.assertEqual(
			expected_anonymized_origin2,
			anonymized_session2.remote_origin.exploded,
		)

if __name__ == '__main__':
	if '--db' in sys.argv:
		index = sys.argv.index('--db')
		if len(sys.argv) - 1 <= index:
			print('missing db url, usage:')
			print(' --db "dialect://user:password@server"')
			quit()
		db_url = sys.argv[index + 1]
		print('using specified db: "' + db_url + '"')
		del sys.argv[index:]
	else:
		print('using sqlite:///:memory:')
	print(
		'use --db [url] to test with specified db url'
			+ ' (e.g. sqlite:///users_tests.db)'
	)
	unittest.main()
