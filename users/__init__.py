import uuid
import time
import re
from ipaddress import ip_address
from enum import Enum
from datetime import datetime, timezone

from sqlalchemy import Table, Column, PrimaryKeyConstraint, LargeBinary as sqla_binary
from sqlalchemy import Integer, String, MetaData
from sqlalchemy.dialects.mysql import VARBINARY as mysql_binary
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import func, and_, or_

from statement_helper import sort_statement, paginate_statement, id_filter
from statement_helper import time_cutoff_filter, string_equal_filter
from statement_helper import string_like_filter, bitwise_filter
from statement_helper import remote_origin_filter
from idcollection import IDCollection
from parse_id import parse_id, get_id_bytes, generate_or_parse_id

def parse_status(status):
	if isinstance(status, str):
		status = UserStatus[status.upper()]
	elif isinstance(status, int):
		status = UserStatus(status)
	elif not isinstance(status, UserStatus):
		raise TypeError('Unable to convert to user status')
	return status

def contains_all_bits(haystack_bits, needle_bits):
	if isinstance(needle_bits, bytes):
		needle_bits = int.from_bytes(needle_bits, 'big')
	if isinstance(haystack_bits, bytes):
		haystack_bits = int.from_bytes(haystack_bits, 'big')
	if (needle_bits == (haystack_bits & needle_bits)):
		return True
	return False

class UserStatus(Enum):
	DEACTIVATED_BY_STAFF = -2
	DEACTIVATED_BY_SELF = -1
	AWAITING_ACTIVATION = 0
	ACTIVATED = 1

	def __int__(self):
		return self.value

	def __str__(self):
		return self.name

class User:
	def __init__(
			self,
			id=None,
			creation_time=None,
			touch_time=None,
			status=UserStatus.AWAITING_ACTIVATION,
			name='',
			display='',
			last_seen_time=0,
			protected=False,
			permissions={},
			authentications={},
		):
		self.id, self.id_bytes = generate_or_parse_id(id)

		current_time = time.time()

		if None == creation_time:
			creation_time = current_time
		self.creation_time = int(creation_time)
		self.creation_datetime = datetime.fromtimestamp(
			self.creation_time,
			timezone.utc,
		)

		if None == touch_time:
			touch_time = current_time
		self.touch_time = int(touch_time)
		self.touch_datetime = datetime.fromtimestamp(
			self.touch_time,
			timezone.utc,
		)

		self.status = parse_status(status)

		self.name = str(name)
		if re.compile(r'[^a-zA-Z0-9_\-]').search(self.name):
			raise ValueError(
				'User name must contain only a-z, A-Z, 0-9, _, and -'
			)

		self.display = str(display)
		self.last_seen_time = int(last_seen_time)
		self.last_seen_datetime = datetime.fromtimestamp(
			self.last_seen_time,
			timezone.utc,
		)

		self.protected = (True == protected)
		self.authentications = authentications
		self.permissions = permissions

		self.identifier = self.id

	def is_active(self):
		if UserStatus.ACTIVATED == self.status:
			return True
		return False

	def has_permission(self, scope='', **kwargs):
		scope = str(scope)
		if scope in self.permissions:
			if 'group_bits' in kwargs:
				if contains_all_bits(
						self.permissions[scope].group_bits,
						kwargs['group_bits'],
					):
					return True
			elif 'group_names' in kwargs:
				if not isinstance(kwargs['group_names'], list):
					kwargs['group_names'] = [kwargs['group_names']]
				matched_all = True
				for group_name in kwargs['group_names']:
					if group_name not in self.permissions[scope].group_names:
						matched_all = False
						break
				if matched_all:
					return True
		# scope was specified
		if scope:
			# also check for permission in global scope
			return self.has_permission(**kwargs)
		return False

class Invite:
	def __init__(
			self,
			id=None,
			creation_time=None,
			redeem_time=0,
			created_by_user_id='',
			redeemed_by_user_id='',
		):
		self.id, self.id_bytes = generate_or_parse_id(id)

		if None == creation_time:
			creation_time = time.time()
		self.creation_time = int(creation_time)
		self.creation_datetime = datetime.fromtimestamp(
			self.creation_time,
			timezone.utc,
		)

		self.redeem_time = int(redeem_time)
		self.redeem_datetime = datetime.fromtimestamp(
			self.redeem_time,
			timezone.utc,
		)

		self.created_by_user_id, self.created_by_user_id_bytes = parse_id(
			created_by_user_id,
		)
		self.redeemed_by_user_id, self.redeemed_by_user_id_bytes = parse_id(
			redeemed_by_user_id,
		)
		self.created_by_user = None
		self.redeemed_by_user = None

	def is_redeemed(self):
		if 0 != self.redeem_time:
			return True
		return False

class Session:
	def __init__(
			self,
			id=None,
			creation_time=None,
			user_id='',
			remote_origin='127.0.0.1',
			useragent_id='',
			touch_time=None,
			close_time=0,
			useragent='',
		):
		self.id, self.id_bytes = generate_or_parse_id(id)

		current_time = time.time()

		if None == creation_time:
			creation_time = current_time
		self.creation_time = int(creation_time)
		self.creation_datetime = datetime.fromtimestamp(
			self.creation_time,
			timezone.utc,
		)

		self.user_id, self.user_id_bytes = parse_id(user_id)
		self.user = None

		self.remote_origin = ip_address(remote_origin)

		self.useragent_id, self.useragent_id_bytes = parse_id(useragent_id)

		if None == touch_time:
			touch_time = current_time
		self.touch_time = int(touch_time)
		self.touch_datetime = datetime.fromtimestamp(
			self.touch_time,
			timezone.utc,
		)

		self.close_time = int(close_time)
		self.close_datetime = datetime.fromtimestamp(
			self.close_time,
			timezone.utc,
		)
		self.useragent = str(useragent)

class Authentication:
	def __init__(
			self,
			id=None,
			creation_time=None,
			user_id='',
			service='',
			value='',
			forbidden=False,
		):
		self.id, self.id_bytes = generate_or_parse_id(id)

		self.user_id, self.user_id_bytes = parse_id(user_id)
		self.user = None

		self.service = str(service)
		self.value = str(value)

		if None == creation_time:
			creation_time = time.time()
		self.creation_time = int(creation_time)
		self.creation_datetime = datetime.fromtimestamp(
			self.creation_time,
			timezone.utc,
		)

		self.forbidden = bool(forbidden)

class Permission:
	def __init__(
			self,
			id=None,
			creation_time=None,
			user_id='',
			scope='',
			group_bits=0,
			group_names=[],
		):
		self.id, self.id_bytes = generate_or_parse_id(id)

		if None == creation_time:
			creation_time = time.time()
		self.creation_time = int(creation_time)
		self.creation_datetime = datetime.fromtimestamp(
			self.creation_time,
			timezone.utc,
		)

		self.user_id, self.user_id_bytes = parse_id(user_id)
		self.user = None

		self.scope = str(scope)

		if isinstance(group_bits, int):
			group_bits = group_bits.to_bytes(2, 'big')
		else:
			group_bits = bytes(group_bits)
		self.group_bits = group_bits

		if not isinstance(group_names, list):
			group_names = [group_names]
		self.group_names = []
		for group_name in group_names:
			self.group_names.append(str(group_name))

class AutoPermission:
	def __init__(
			self,
			id=None,
			creation_time=None,
			user_id='',
			scope='',
			group_bits=0,
			group_names=[],
			duration=0,
			valid_from_time=0,
			valid_until_time=0,
			created_by_user_id='',
		):
		self.id, self.id_bytes = generate_or_parse_id(id)

		permission = Permission(
			self.id_bytes,
			creation_time,
			user_id,
			scope,
			group_bits,
			group_names,
		)
		self.creation_time = permission.creation_time
		self.creation_datetime = permission.creation_datetime
		self.user_id = permission.user_id
		self.user_id_bytes = permission.user_id_bytes
		self.user = permission.user
		self.scope = permission.scope
		self.group_bits = permission.group_bits
		self.group_names = permission.group_names

		self.duration = int(duration)

		self.valid_from_time = int(valid_from_time)
		self.valid_from_datetime = datetime.fromtimestamp(
			self.valid_from_time,
			timezone.utc,
		)

		self.valid_until_time = int(valid_until_time)
		self.valid_until_datetime = datetime.fromtimestamp(
			self.valid_until_time,
			timezone.utc,
		)

		self.created_by_user_id, self.created_by_user_id_bytes = parse_id(created_by_user_id)
		self.created_by_user = None

class Users:
	def __init__(self, engine, db_prefix='', install=False, connection=None):
		self.engine = engine
		self.engine_session = sessionmaker(bind=self.engine)()

		self.db_prefix = db_prefix

		self.authentication_service_length = 8
		self.authentication_value_length = 256
		self.group_name_length = 16
		self.scope_length = 16
		self.group_bits_length = 64 # in bytes

		self.require_unique_names = False
		self.require_unique_displays = False

		self.available_scopes = []

		self.available_groups = []
		self.group_names_to_bits = {}

		self.name_length = 16
		self.display_length = 16

		self.useragents_length = 128

		metadata = MetaData()

		default_bytes = 0b0 * 16

		if 'mysql' == self.engine_session.bind.dialect.name:
			Binary = mysql_binary
		else:
			Binary = sqla_binary

		# users tables
		self.users = Table(
			self.db_prefix + 'users',
			metadata,
			Column('id', Binary(16), default=default_bytes),
			Column('creation_time', Integer, default=0),
			Column('touch_time', Integer, default=0),
			Column(
				'status',
				Integer,
				default=int(UserStatus.AWAITING_ACTIVATION),
			),
			Column('name', String(self.name_length), default=''),
			Column('display', String(self.display_length), default=''),
			PrimaryKeyConstraint('id'),
		)

		# protections tables
		self.protections = Table(
			self.db_prefix + 'protections',
			metadata,
			Column('user_id', Binary(16), default=default_bytes),
			PrimaryKeyConstraint('user_id'),
		)

		# invites tables
		self.invites = Table(
			self.db_prefix + 'invites',
			metadata,
			Column('id', Binary(16), default=default_bytes),
			Column('creation_time', Integer, default=0),
			Column('redeem_time', Integer, default=0),
			Column('created_by_user_id', Binary(16), default=default_bytes),
			Column('redeemed_by_user_id', Binary(16), default=default_bytes),
			PrimaryKeyConstraint('id'),
		)

		# sessions tables
		self.useragents = Table(
			self.db_prefix + 'useragents',
			metadata,
			Column('id', Binary(16), default=default_bytes),
			Column('useragent', String(self.useragents_length), default=''),
			PrimaryKeyConstraint('id'),
		)
		self.sessions = Table(
			self.db_prefix + 'sessions',
			metadata,
			Column('id', Binary(16), default=default_bytes),
			Column('creation_time', Integer, default=0),
			Column('user_id', Binary(16), default=default_bytes),
			Column(
				'remote_origin',
				Binary(16),
				default=ip_address(default_bytes).packed,
			),
			Column('useragent_id', Binary(16), default=default_bytes),
			Column('touch_time', Integer, default=0),
			Column('close_time', Integer, default=0),
			PrimaryKeyConstraint('id'),
		)

		# authentications tables
		self.authentications = Table(
			self.db_prefix + 'authentications',
			metadata,
			Column('id', Binary(16), default=default_bytes),
			Column('creation_time', Integer, default=0),
			Column('user_id', Binary(16), default=default_bytes),
			Column(
				'service',
				String(self.authentication_service_length),
				default='',
			),
			Column('value', String(self.authentication_value_length), default=''),
			Column('forbidden', Integer, default=0),
			PrimaryKeyConstraint('id'),
		)

		# scopes tables
		self.scopes = Table(
			self.db_prefix + 'scopes',
			metadata,
			Column('scope', String(self.scope_length)),
			PrimaryKeyConstraint('scope'),
		)

		# groups tables
		self.groups = Table(
			self.db_prefix + 'groups',
			metadata,
			Column('name', String(self.group_name_length)),
			Column('bit', Integer, default=0),
			PrimaryKeyConstraint('name'),
		)

		# permissions tables
		self.permissions = Table(
			self.db_prefix + 'permissions',
			metadata,
			Column('id', Binary(16), default=default_bytes),
			Column('creation_time', Integer, default=0),
			Column('user_id', Binary(16), default=default_bytes),
			Column('scope', String(self.scope_length), default=''),
			Column('group_bits', Integer, default=0),
			PrimaryKeyConstraint('id'),
		)

		# auto permissions tables
		self.auto_permissions = Table(
			self.db_prefix + 'auto_permissions',
			metadata,
			Column('id', Binary(16), default=default_bytes),
			Column('creation_time', Integer, default=0),
			Column('user_id', Binary(16), default=default_bytes),
			Column('scope', String(self.scope_length), default=''),
			Column('group_bits', Integer, default=0),
			Column('duration', Integer, default=0),
			Column('valid_from_time', Integer, default=0),
			Column('valid_until_time', Integer, default=0),
			Column('created_by_user_id', Binary(16), default=default_bytes),
		)

		if connection:
			self.connection = connection
		else:
			self.connection = self.engine.connect()

		if install:
			for table in [
					self.users,
					self.protections,
					self.invites,
					self.useragents,
					self.sessions,
					self.authentications,
					self.scopes,
					self.groups,
					self.permissions,
					self.auto_permissions,
				]:
				table.create(bind=self.engine, checkfirst=True)

	def uninstall(self):
		for table in [
				self.users,
				self.protections,
				self.invites,
				self.useragents,
				self.sessions,
				self.authentications,
				self.scopes,
				self.groups,
				self.permissions,
				self.auto_permissions,
			]:
			table.drop(self.engine)

	# scopes
	def populate_scopes(self):
		self.available_scopes = []
		self.protected_scopes = []
		result = self.connection.execute(
			self.scopes.select().order_by(self.scopes.c.scope.asc())
		)
		for row in result:
			self.available_scopes.append(row[self.scopes.c.scope])
		# if global scope exists put it at the beginning of available scopes
		if '' in self.available_scopes:
			self.available_scopes.remove('')
		self.available_scopes.insert(0, '')

	def create_scope(self, scope):
		self.populate_scopes()
		if scope in self.available_scopes:
			return
		self.connection.execute(
			self.scopes.insert(),
			scope=scope
		)

	def delete_scope(self, scope):
		self.populate_groups()
		if scope not in self.available_scopes:
			return
		self.connection.execute(
			self.permissions.delete().where(
				self.permissions.c.scope == scope,
			)
		)
		self.connection.execute(
			self.auto_permissions.delete().where(
				self.auto_permissions.c.scope == scope,
			)
		)
		self.connection.execute(
			self.scopes.delete().where(
				self.scopes.c.scope == scope,
			)
		)

	# groups
	def populate_groups(self):
		self.group_names_to_bits = {}
		result = self.connection.execute(
			self.groups.select().order_by(self.groups.c.name.asc())
		)
		for row in result:
			bit = int(row[self.groups.c.bit]).to_bytes(2, 'big')
			self.group_names_to_bits[row[self.groups.c.name]] = bit
		self.available_groups = list(self.group_names_to_bits.keys())

	def create_group(self, name, bit=None):
		self.populate_groups()
		if name in self.available_groups:
			return
		if bit:
			if isinstance(bit, bytes):
				bit_int = int.from_bytes(bit, 'big')
				bit_bytes = bit
			elif isinstance(bit, int):
				bit_int = bit
				bit_bytes = int.to_bytes(bit, 2, 'big')
			else:
				raise TypeError
			if bit_bytes in self.group_names_to_bits.values():
				raise ValueError('Specified group bit is already in use')
		else:
			bit_int = self.group_bits_length * 8
			while bit_int > 0:
				in_use = False
				for group_bit in self.group_names_to_bits.values():
					if int.from_bytes(group_bit, 'big') == bit_int:
						in_use = True
						break
				if not in_use:
					break
				bit_int = bit_int >> 1
			if bit_int <= 0:
				raise ValueError('No available group bits, please increase column size')
			
		self.connection.execute(
			self.groups.insert(),
			name=str(name),
			bit=int(bit_int),
		)

	def delete_group(self, name):
		self.populate_groups()
		if name not in self.available_groups:
			return
		bit_int = int.from_bytes(self.group_name_to_bit(name), 'big')
		self.connection.execute(
			self.permissions.delete().where(
				and_(
					self.permissions.c.group_bits.op('&')(bit_int) == bit_int,
				).self_group(),
			)
		)
		self.connection.execute(
			self.auto_permissions.delete().where(
				and_(
					self.auto_permissions.c.group_bits.op('&')(bit_int) == bit_int,
				).self_group(),
			)
		)
		self.connection.execute(
			self.groups.delete().where(
				self.groups.c.name == name,
			)
		)

	def group_name_to_bit(self, name):
		if name not in self.group_names_to_bits:
			return int(0).to_bytes(2, 'big')
		return self.group_names_to_bits[name]

	def combine_groups(self, names=[], bits=[]):
		if list is not type(names):
			names = [names]
		if list is not type(bits):
			bits = [bits]
		combined = 0
		if 0 < len(names):
			for name in names:
				bit = self.group_name_to_bit(name)
				combined = combined | int.from_bytes(bit, 'big')
		if 0 < len(bits):
			for bit in bits:
				if isinstance(bit, bytes):
					bit = int.from_bytes(bit, 'big')
				combined = combined | bit
		return combined.to_bytes(2, 'big')

	def contains_all_bits(self, haystack_bits, needle_bits):
		return contains_all_bits(haystack_bits, needle_bits)

	def group_names_from_bits(self, group_bits):
		group_names = []
		for group_name, group_bit in self.group_names_to_bits.items():
			if contains_all_bits(group_bits, group_bit):
				group_names.append(group_name)
		return group_names

	# users supplemental
	def check_duplicate_name(self, user):
		if not user.name:
			return
		users = self.search_users(filter={'names': user.name})
		users.remove(user)
		if 0 < len(users):
			raise ValueError('User name collision')

	def check_duplicate_display(self, user):
		if not user.display:
			return
		users = self.search_users(filter={'displays': user.display})
		users.remove(user)
		if 0 < len(users):
			raise ValueError('User display collision')

	# retrieve users
	def get_user(self, id):
		users = self.search_users(filter={'ids': id})
		return users.get(id)

	def prepare_users_search_conditions(self, filter):
		conditions = []
		conditions += id_filter(filter, 'ids', self.users.c.id)
		conditions += time_cutoff_filter(
			filter,
			'created',
			self.users.c.creation_time,
		)
		conditions += time_cutoff_filter(
			filter,
			'touched',
			self.users.c.touch_time,
		)
		if 'statuses' in filter:
			if list is not type(filter['statuses']):
				filter['statuses'] = [filter['statuses']]
			block_conditions = []
			for status in filter['statuses']:
				try:
					status = parse_status(status)
				except:
					pass
				else:
					block_conditions.append(self.users.c.status == int(status))
			if block_conditions:
				conditions.append(or_(*block_conditions))
			else:
				conditions.append(False)
		conditions += string_like_filter(filter, 'names', self.users.c.name)
		conditions += string_like_filter(
			filter,
			'displays',
			self.users.c.display,
		)
		if 'last_seen_time' in filter:
			last_seen_time_subquery = self.engine_session.query(
				self.sessions.c.user_id, func.max(self.sessions.c.touch_time)
			).group_by(self.sessions.c.user_id).subquery()
			conditions += time_cutoff_filter(
				filter,
				'last_seen_time',
				last_seen_time_subquery.c.touch_time,
			)
		if 'protection' in filter:
			protections_subquery = self.engine_session.query(
				self.protections.c.user_id
			).subquery()
			if filter['protection']:
				conditions.append(self.users.c.id.in_(protections_subquery))
			else:
				conditions.append(self.users.c.id.notin_(protections_subquery))
		return conditions

	def count_users(self, filter={}):
		statement = self.users.select()
		conditions = self.prepare_users_search_conditions(filter)
		if conditions:
			statement = statement.where(and_(*conditions))
		statement = statement.with_only_columns([func.count(self.users.c.id)])
		return self.connection.execute(statement).fetchone()[0]

	def search_users(
			self,
			filter={},
			sort='',
			order='',
			page=0,
			perpage=None,
		):
		conditions = self.prepare_users_search_conditions(filter)

		last_seen_time_subquery = self.engine_session.query(
			self.sessions.c.user_id, func.max(self.sessions.c.touch_time)
		).group_by(self.sessions.c.user_id).subquery()

		protections_subquery = self.engine_session.query(
			self.protections.c.user_id
		).subquery()

		statement = self.users.join(
			last_seen_time_subquery,
			last_seen_time_subquery.c.user_id == self.users.c.id,
			isouter=True,
		).join(
			protections_subquery,
			protections_subquery.c.user_id == self.users.c.id,
			isouter=True,
		).select()
		if conditions:
			statement = statement.where(and_(*conditions))

		user_id, last_seen_time_column = last_seen_time_subquery.c

		if 'last_seen_time' == sort:
			sort = last_seen_time_column

		statement = sort_statement(
			statement,
			self.users,
			sort,
			order,
			last_seen_time_column,
			True,
			[
				'creation_time',
				'id',
			]
		)
		statement = paginate_statement(statement, page, perpage)

		result = self.connection.execute(statement).fetchall()

		users = IDCollection()
		for row in result:
			last_seen_time = 0
			if row[last_seen_time_column]:
				last_seen_time = row[last_seen_time_column]

			protected = False
			if row[protections_subquery.c.user_id]:
				protected = True

			user = User(
				id=row[self.users.c.id],
				creation_time=row[self.users.c.creation_time],
				touch_time=row[self.users.c.touch_time],
				status=UserStatus(row[self.users.c.status]),
				name=row[self.users.c.name],
				display=row[self.users.c.display],
				last_seen_time=int(last_seen_time),
				protected=protected,
			)
			if self.require_unique_names and user.name:
				user.identifier = user.name
			users.add(user)

		return users

	# manipulate users
	def create_user(self, **kwargs):
		user = User(**kwargs)
		# preflight check for existing id
		if self.get_user(user.id_bytes):
			raise ValueError('User ID collision')
		if self.require_unique_names:
			self.check_duplicate_name(user)
		if self.require_unique_displays:
			self.check_duplicate_display(user)
		self.connection.execute(
			self.users.insert(),
			id=user.id_bytes,
			creation_time=int(user.creation_time),
			touch_time=int(user.touch_time),
			status=int(user.status),
			name=str(user.name),
			display=str(user.display),
		)
		if self.require_unique_names and user.name:
			user.identifier = user.name
		return user

	def update_user(self, id, **kwargs):
		user = User(id=id, **kwargs)
		updates = {}
		if 'creation_time' in kwargs:
			updates['creation_time'] = int(user.creation_time)
		if 'touch_time' in kwargs:
			updates['touch_time'] = int(user.touch_time)
		else:
			updates['touch_time'] = int(time.time())
		if 'status' in kwargs:
			updates['status'] = int(user.status)
		if 'name' in kwargs:
			if self.require_unique_names:
				self.check_duplicate_name(user)
			updates['name'] = str(user.name)
		if 'display' in kwargs:
			if self.require_unique_displays:
				self.check_duplicate_display(user)
			updates['display'] = str(user.display)
		if 0 == len(updates):
			return
		self.connection.execute(
			self.users.update().values(**updates).where(
				self.users.c.id == user.id_bytes
			)
		)

	def protect_user(self, id):
		id = get_id_bytes(id)
		# preflight check for already protected
		statement = self.users.select().with_only_columns(
			[func.count(self.protections.c.user_id)]
		).where(
			self.protections.c.user_id == id
		)
		if self.connection.execute(statement).fetchone()[0]:
			return
		self.connection.execute(
			self.protections.insert(),
			user_id=id,
		)

	def unprotect_user(self, id):
		id = get_id_bytes(id)
		self.connection.execute(
			self.protections.delete().where(
				self.protections.c.user_id == id
			)
		)

	def delete_user(self, id):
		id = get_id_bytes(id)
		self.connection.execute(
			self.users.delete().where(self.users.c.id == id)
		)

	# retrieve invites
	def get_invite(self, id):
		invites = self.search_invites(filter={'ids': id})
		return invites.get(id)

	def prepare_invites_search_statement(self, filter):
		conditions = []
		conditions += id_filter(filter, 'ids', self.invites.c.id)
		conditions += time_cutoff_filter(
			filter,
			'created',
			self.invites.c.creation_time,
		)
		conditions += time_cutoff_filter(filter, 'redeemed', self.invites.c.redeem_time)
		conditions += id_filter(
			filter,
			'created_by_user_ids',
			self.invites.c.created_by_user_id,
		)
		conditions += id_filter(
			filter,
			'redeemed_by_user_ids',
			self.invites.c.redeemed_by_user_id,
		)

		statement = self.invites.select()
		if conditions:
			statement = statement.where(and_(*conditions))
		return statement

	def count_invites(self, filter={}):
		statement = self.prepare_invites_search_statement(filter)
		statement = statement.with_only_columns([func.count(self.invites.c.id)])
		return self.connection.execute(statement).fetchone()[0]

	def search_invites(
			self,
			filter={},
			sort='',
			order='',
			page=0,
			perpage=None
		):
		statement = self.prepare_invites_search_statement(filter)

		statement = sort_statement(
			statement,
			self.invites,
			sort,
			order,
			'creation_time',
			True,
			[
				'creation_time',
				'id',
			],
		)
		statement = paginate_statement(statement, page, perpage)

		result = self.connection.execute(statement).fetchall()
		if 0 == len(result):
			return IDCollection()

		user_ids = []
		for row in result:
			if row[self.invites.c.created_by_user_id]:
				user_ids.append(row[self.invites.c.created_by_user_id])
			if row[self.invites.c.redeemed_by_user_id]:
				user_ids.append(row[self.invites.c.redeemed_by_user_id])

		if user_ids:
			users = self.search_users(filter={'ids': user_ids})
		else:
			users = IDCollection()

		invites = IDCollection()
		for row in result:
			invite = Invite(
				row[self.invites.c.id],
				creation_time=row[self.invites.c.creation_time],
				redeem_time=row[self.invites.c.redeem_time],
				created_by_user_id=row[self.invites.c.created_by_user_id],
				redeemed_by_user_id=row[self.invites.c.redeemed_by_user_id],
			)

			if invite.created_by_user_id in users:
				invite.created_by_user = users.get(invite.created_by_user_id)

			if invite.redeemed_by_user_id in users:
				invite.redeemed_by_user = users.get(invite.redeemed_by_user_id)

			invites.add(invite)
		return invites

	# manipulate invites
	def create_invite(self, **kwargs):
		invite = Invite(**kwargs)
		# preflight check for existing id
		if self.get_invite(invite.id_bytes):
			raise ValueError('Invite ID collision')
		self.connection.execute(
			self.invites.insert(),
			id=invite.id_bytes,
			creation_time=int(invite.creation_time),
			redeem_time=int(invite.redeem_time),
			created_by_user_id=invite.created_by_user_id_bytes,
			redeemed_by_user_id=invite.redeemed_by_user_id_bytes,
		)
		return invite

	def redeem_invite(self, id, user_id, redeem_time=None):
		invite = self.get_invite(id)
		if not invite:
			raise ValueError('Invite not found')
		if invite.is_redeemed():
			raise ValueError('Invite already redeemed')
		user_id = get_id_bytes(user_id)
		if not redeem_time:
			redeem_time = int(time.time())
		self.connection.execute(
			self.invites.update().values(
				redeemed_by_user_id=user_id,
				redeem_time=redeem_time,
			).where(
				self.invites.c.id == invite.id_bytes
			)
		)

	def delete_invite(self, id):
		id = get_id_bytes(id)
		self.connection.execute(
			self.invites.delete().where(self.invites.c.id == id)
		)

	# retrieve sessions
	def get_useragent_id(self, useragent):
		result = self.connection.execute(
			self.useragents.select().where(
				self.useragents.c.useragent == str(useragent)[:self.useragents_length]
			)
		).fetchone()
		if not result:
			return None
		return result[self.useragents.c.id]

	def get_session(self, id):
		sessions = self.search_sessions(filter={'ids': id})
		return sessions.get(id)

	def prepare_sessions_search_conditions(self, filter, useragents_subquery):
		conditions = []
		conditions += id_filter(filter, 'ids', self.sessions.c.id)
		conditions += time_cutoff_filter(
			filter,
			'created',
			self.sessions.c.creation_time,
		)
		conditions += id_filter(
			filter,
			'user_ids',
			self.sessions.c.user_id,
		)
		conditions += remote_origin_filter(
			filter,
			'remote_origins',
			self.sessions.c.remote_origin,
		)
		if 'useragents' in filter:
			truncated_useragents = []
			for useragent in filter['useragents']:
				truncated_useragents.append(useragent[:self.useragents_length])
		conditions += string_equal_filter(
			filter,
			'useragents',
			useragents_subquery.c.useragent,
		)
		conditions += id_filter(
			filter,
			'useragent_ids',
			self.sessions.c.useragent_id,
		)
		conditions += time_cutoff_filter(
			filter,
			'touched',
			self.sessions.c.touch_time,
		)
		conditions += time_cutoff_filter(
			filter,
			'closed',
			self.sessions.c.close_time,
		)
		return conditions

	def count_sessions(self, filter={}):
		useragents_subquery = self.engine_session.query(
			self.useragents.c.id,
			self.useragents.c.useragent,
		).subquery()
		statement = self.sessions.join(
			useragents_subquery,
			useragents_subquery.c.id == self.sessions.c.useragent_id,
			isouter=True
		).select()
		conditions = self.prepare_sessions_search_conditions(
			filter,
			useragents_subquery,
		)
		if conditions:
			statement = statement.where(and_(*conditions))
		statement = statement.with_only_columns([func.count(self.sessions.c.id)])
		return self.connection.execute(statement).fetchone()[0]

	def search_sessions(
			self,
			filter={},
			sort='',
			order='',
			page=0,
			perpage=None
		):
		useragents_subquery = self.engine_session.query(
			self.useragents.c.id,
			self.useragents.c.useragent,
		).subquery()
		statement = self.sessions.join(
			useragents_subquery,
			useragents_subquery.c.id == self.sessions.c.useragent_id,
			isouter=True
		).select()

		conditions = self.prepare_sessions_search_conditions(
			filter,
			useragents_subquery,
		)

		if conditions:
			statement = statement.where(and_(*conditions))

		statement = sort_statement(
			statement,
			self.sessions,
			sort,
			order,
			self.sessions.c.touch_time,
			True,
			[
				'creation_time',
				'id',
			]
		)
		statement = paginate_statement(statement, page, perpage)

		result = self.connection.execute(statement).fetchall()

		user_ids = []
		for row in result:
			user_ids.append(row[self.sessions.c.user_id])

		users = self.search_users(filter={'ids': user_ids})

		sessions = IDCollection()
		for row in result:
			useragent = ''
			if row[useragents_subquery.c.useragent]:
				useragent = row[useragents_subquery.c.useragent]
			session = Session(
				row[self.sessions.c.id],
				creation_time=row[self.sessions.c.creation_time],
				user_id=row[self.sessions.c.user_id],
				remote_origin=ip_address(row[self.sessions.c.remote_origin]).exploded,
				useragent_id=row[self.sessions.c.useragent_id],
				touch_time=row[self.sessions.c.touch_time],
				close_time=row[self.sessions.c.close_time],
				useragent=useragent,
			)
			if session.user_id in users:
				session.user = users.get(session.user_id)
			sessions.add(session)

		return sessions

	# manipulate sessions
	def create_useragent(self, useragent):
		useragent = useragent[:self.useragents_length]
		# preflight check for existing id
		id = self.get_useragent_id(useragent)
		if not id:
			id = uuid.uuid4().bytes
			self.connection.execute(
				self.useragents.insert(),
				id=id,
				useragent=str(useragent),
			)
		return id

	def delete_useragent(self, useragent):
		useragent = useragent[:self.useragents_length]
		self.connection.execute(
			self.useragents.delete().where(
				self.useragents.c.useragent == str(useragent)
			)
		)

	def create_session(self, **kwargs):
		if 'useragent' in kwargs:
			kwargs['useragent'] = kwargs['useragent'][:self.useragents_length]
			kwargs['useragent_id'] = self.create_useragent(kwargs['useragent'])
		session = Session(**kwargs)
		# preflight check for existing id
		if self.count_sessions(filter={'ids': session.id_bytes}):
			raise ValueError('Session ID collision')
		self.connection.execute(
			self.sessions.insert(),
			id=session.id_bytes,
			creation_time=int(session.creation_time),
			user_id=session.user_id_bytes,
			remote_origin=session.remote_origin.packed,
			useragent_id=session.useragent_id_bytes,
			touch_time=int(session.touch_time),
			close_time=int(session.close_time),
		)
		return session

	def touch_session(self, id, touch_time=None):
		id = get_id_bytes(id)
		if not touch_time:
			touch_time = time.time()
		self.connection.execute(
			self.sessions.update().values(
				touch_time=int(touch_time),
			).where(self.sessions.c.id == id)
		)

	def close_session(self, id, close_time=None):
		id = get_id_bytes(id)
		session = self.get_session(id)
		if not session:
			raise ValueError('Session did not exist')
		if 0 < session.close_time:
			raise ValueError('Session was already closed')
		if not close_time:
			close_time = time.time()
		self.connection.execute(
			self.sessions.update().values(
				close_time=int(close_time),
			).where(self.sessions.c.id == id)
		)

	def close_user_sessions(self, user_id, close_time=None):
		user_id = get_id_bytes(user_id)
		if not close_time:
			close_time = time.time()
		self.connection.execute(
			self.sessions.update().values(
				close_time=int(close_time),
			).where(
				and_(
					self.sessions.c.close_time == 0,
					self.sessions.c.user_id == user_id,
				)
			)
		)

	def prune_sessions(self, closed_before=None):
		conditions = [0 != self.sessions.c.close_time]
		if closed_before:
			conditions.append(int(closed_before) > self.sessions.c.close_time)
		self.connection.execute(
			self.sessions.delete().where(and_(*conditions))
		)

	def delete_session(self, id):
		id = get_id_bytes(id)
		self.connection.execute(
			self.sessions.delete().where(self.sessions.c.id == id)
		)

	# retrieve authentications
	def get_authentication(self, id):
		authentications = self.search_authentications(filter={'ids': id})
		return authentications.get(id)

	def get_authentication_value(self, user_id, service):
		authentications = self.search_authentications(
			filter={
				'user_ids': user_id,
				'services': service,
			}
		)
		if 1 != len(authentications):
			return None
		return authentications.values()[0].value

	def get_authentication_user_id(self, service, value):
		authentications = self.search_authentications(
			filter={
				'services': service,
				'values': value,
			}
		)
		if 1 != len(authentications):
			return None
		return authentications.values()[0].user_id

	def get_user_authentications(self, user_id):
		return self.search_authentications(filter={'user_ids': user_id})

	def prepare_authentications_search_statement(self, filter={}):
		conditions = []
		conditions += id_filter(filter, 'ids', self.authentications.c.id)
		conditions += time_cutoff_filter(
			filter,
			'created',
			self.authentications.c.creation_time,
		)
		conditions += id_filter(
			filter,
			'user_ids',
			self.authentications.c.user_id,
		)
		conditions += string_equal_filter(
			filter,
			'services',
			self.authentications.c.service,
		)
		conditions += string_like_filter(
			filter,
			'values',
			self.authentications.c.value,
		)
		if 'forbidden' in filter:
			forbidden = 0
			if filter['forbidden']:
				forbidden = 1
			conditions.append(self.authentications.c.forbidden == int(forbidden))

		statement = self.authentications.select()
		if conditions:
			statement = statement.where(and_(*conditions))
		return statement

	def count_authentications(self, filter={}):
		statement = self.prepare_authentications_search_statement(filter)
		statement = statement.with_only_columns(
			[func.count(self.authentications.c.id)]
		)
		return self.connection.execute(statement).fetchone()[0]

	def search_authentications(
			self,
			filter={},
			sort='',
			order='',
			page=0,
			perpage=None
		):
		statement = self.prepare_authentications_search_statement(filter)

		statement = sort_statement(
			statement,
			self.authentications,
			sort,
			order,
			'creation_time',
			True,
			[
				'creation_time',
				'id',
			],
		)
		statement = paginate_statement(statement, page, perpage)

		result = self.connection.execute(statement).fetchall()
		if 0 == len(result):
			return IDCollection()

		user_ids = []
		for row in result:
			if row[self.authentications.c.user_id]:
				user_ids.append(row[self.authentications.c.user_id])

		if user_ids:
			users = self.search_users(filter={'ids': user_ids})
		else:
			users = IDCollection()

		authentications = IDCollection()
		for row in result:
			authentication = Authentication(
				row[self.authentications.c.id],
				creation_time=row[self.authentications.c.creation_time],
				user_id=row[self.authentications.c.user_id],
				service=row[self.authentications.c.service],
				value=row[self.authentications.c.value],
				forbidden=row[self.authentications.c.forbidden],
			)

			if authentication.user_id in users:
				authentication.user = users.get(authentication.user_id)

			authentications.add(authentication)

		return authentications

	def populate_user_authentications(self, user):
		authentications = self.get_user_authentications(user.id_bytes)
		user.authentications = {}
		for authentication in authentications.values():
			user.authentications[authentication.service] = authentication

	# manipulate authentications
	def create_authentication(self, **kwargs):
		authentication = Authentication(**kwargs)
		# preflight check for existing authentication user_id/service pair
		auth_count = self.count_authentications(
				filter={
					'user_ids': authentication.user_id_bytes,
					'services': authentication.service,
				}
			)
		if auth_count:
			raise ValueError(
				'An authentication for this user and service already exists'
			)
		# preflight check for existing authentication service/value pair
		existing_authentications = self.search_authentications(
			filter={
				'services': authentication.service,
				'values': authentication.value,
			}
		)
		if 0 < len(existing_authentications):
			existing_authentication = existing_authentications.values()[0]
			if existing_authentication.forbidden:
				raise ValueError('This authentication has been forbidden')
			if existing_authentication.user_id == authentication.user_id:
				return existing_authentication
			raise ValueError(
				'This authentication already exists for a different user'
			)
		self.connection.execute(
			self.authentications.insert(),
			id=authentication.id_bytes,
			user_id=authentication.user_id_bytes,
			service=str(authentication.service),
			value=str(authentication.value),
			creation_time=int(authentication.creation_time),
			forbidden=int(authentication.forbidden),
		)
		return authentication

	def forbid_authentication(self, id):
		id = get_id_bytes(id)
		self.connection.execute(
			self.authentications.update().values(forbidden=1).where(
				self.authentications.c.id == id,
			)
		)

	def unforbid_authentication(self, id):
		id = get_id_bytes(id)
		self.connection.execute(
			self.authentications.update().values(forbidden=0).where(
				self.authentications.c.id == id,
			)
		)

	def delete_authentication(self, id):
		id = get_id_bytes(id)
		self.connection.execute(
			self.authentications.delete().where(
				self.authentications.c.id == id,
			)
		)

	def delete_user_authentications(self, user_id, service=None):
		user_id = get_id_bytes(user_id)
		conditions = [self.authentications.c.user_id == user_id]
		if service:
			conditions.append(self.authentications.c.service == str(service))
		self.connection.execute(
			self.authentications.delete().where(and_(*conditions))
		)

	def delete_service_authentication_by_value(self, service, value):
		self.connection.execute(
			self.authentications.delete().where(
				and_(
					self.authentications.c.service == str(service),
					self.authentications.c.value == str(value),
				)
			)
		)

	# retrieve permissions
	def get_permission(self, id):
		permissions = self.search_permissions(filter={'ids': id})
		return permissions.get(id)

	def get_user_permission(self, user_id, scope):
		user_id = get_id_bytes(user_id)
		permissions = self.search_permissions(
			filter={'user_ids': user_id, 'scopes': scope}
		)
		if 1 != len(permissions):
			return None
		return permissions.values()[0]

	def get_user_permissions(self, user_id):
		user_id = get_id_bytes(user_id)
		return self.search_permissions(filter={'user_ids': user_id})

	def prepare_permissions_search_statement(self, filter={}):
		conditions = []
		conditions += id_filter(filter, 'ids', self.permissions.c.id)
		conditions += time_cutoff_filter(
			filter,
			'created',
			self.permissions.c.creation_time,
		)
		conditions += id_filter(filter, 'user_ids', self.permissions.c.user_id)
		conditions += string_equal_filter(
			filter,
			'scopes',
			self.permissions.c.scope,
		)
		conditions += bitwise_filter(
			filter,
			'group_bits',
			self.permissions.c.group_bits,
		)

		statement = self.permissions.select()
		if conditions:
			statement = statement.where(and_(*conditions))
		return statement

	def count_permissions(self, filter={}):
		statement = self.prepare_permissions_search_statement(filter)
		statement = statement.with_only_columns(
			[func.count(self.permissions.c.id)]
		)
		return self.connection.execute(statement).fetchone()[0]

	def search_permissions(
			self,
			filter={},
			sort='',
			order='',
			page=0,
			perpage=None
		):
		statement = self.prepare_permissions_search_statement(filter)

		statement = sort_statement(
			statement,
			self.permissions,
			sort,
			order,
			'creation_time',
			True,
			[
				'creation_time',
				'id',
			],
		)
		statement = paginate_statement(statement, page, perpage)

		result = self.connection.execute(statement).fetchall()
		if 0 == len(result):
			return IDCollection()

		user_ids = []
		for row in result:
			if row[self.permissions.c.user_id]:
				user_ids.append(row[self.permissions.c.user_id])

		if user_ids:
			users = self.search_users(filter={'ids': user_ids})
		else:
			users = IDCollection()

		permissions = IDCollection()
		for row in result:
			permission_group_bits = row[self.permissions.c.group_bits]
			group_names = self.group_names_from_bits(permission_group_bits)
			permission = Permission(
				row[self.permissions.c.id],
				creation_time=row[self.permissions.c.creation_time],
				user_id=row[self.permissions.c.user_id],
				scope=row[self.permissions.c.scope],
				group_bits=permission_group_bits,
				group_names=group_names,
			)

			if permission.user_id in users:
				permission.user = users.get(permission.user_id)

			permissions.add(permission)
		return permissions

	def populate_user_permissions(self, user):
		permissions = self.get_user_permissions(user.id_bytes)
		user.permissions = {}
		for permission in permissions.values():
			user.permissions[permission.scope] = permission

	def populate_users_permissions(self, users):
		user_ids = []
		for user in users.values():
			user_ids.append(user.id)
			user.permissions = {}
		permissions = self.search_permissions(filter={'user_ids': user_ids})
		for permission in permissions.values():
			if permission.user in users:
				user = users.get(permission.user)
				if permission.scope not in user.permissions:
					user.permissions[permission.scope] = permission

	# manipulate permissions
	def create_permission(self, **kwargs):
		if 'group_bits' in kwargs and -1 == kwargs['group_bits']:
			kwargs['group_bits'] = 0
			while kwargs['group_bits'] <= (self.group_bits_length * 8):
				kwargs['group_bits'] = (kwargs['group_bits'] << 1) + 1
		opts = {}
		if 'preserve_protected' in kwargs:
			opts['preserve_protected'] = kwargs['preserve_protected']
			del kwargs['preserve_protected']
		permission = Permission(**kwargs)
		# preflight check for existing id
		if self.get_permission(permission.id_bytes):
			raise ValueError('Permission ID collision')
		# delete existing permission with this user_id/scope pair if it exists
		self.delete_permissions(
			user_ids=permission.user_id_bytes,
			scope=permission.scope,
			**opts
		)
		self.connection.execute(
			self.permissions.insert(),
			id=permission.id_bytes,
			creation_time=int(permission.creation_time),
			user_id=permission.user_id_bytes,
			scope=str(permission.scope),
			group_bits=int.from_bytes(permission.group_bits, 'big'),
		)
		return permission

	def delete_permission(self, id):
		id = get_id_bytes(id)
		self.connection.execute(
			self.permissions.delete().where(self.permissions.c.id == id)
		)

	def delete_permissions(
			self,
			user_ids=None,
			scope=None,
			preserve_protected=True,
		):
		conditions = []
		if user_ids:
			block_conditions = []
			if not isinstance(user_ids, list):
				user_ids = [user_ids]
			for user_id in user_ids:
				try:
					user_id = get_id_bytes(user_id)
				except:
					continue
				block_conditions.append(self.permissions.c.user_id == user_id)
			if block_conditions:
				conditions.append(or_(*block_conditions))
			else:
				return

		if preserve_protected:
			protections_subquery = self.engine_session.query(
				self.protections.c.user_id
			).subquery()
			conditions.append(self.permissions.c.user_id.notin_(protections_subquery))
		# explicit check against None
		# in case of global scope which is an empty string
		if None != scope:
			conditions.append(self.permissions.c.scope == str(scope))
		self.connection.execute(
			self.permissions.delete().where(and_(*conditions))
		)

	# retrieve auto permissions
	def get_auto_permission(self, id):
		auto_permissions = self.search_auto_permissions(filter={'ids': id})
		return auto_permissions.get(id)

	def prepare_auto_permissions_search_statement(self, filter={}):
		conditions = []
		conditions += id_filter(filter, 'ids', self.auto_permissions.c.id)
		conditions += time_cutoff_filter(
			filter,
			'created',
			self.auto_permissions.c.creation_time,
		)
		conditions += id_filter(
			filter,
			'user_ids',
			self.auto_permissions.c.user_id,
		)
		conditions += string_equal_filter(
			filter,
			'scopes',
			self.auto_permissions.c.scope,
		)
		conditions += bitwise_filter(
			filter,
			'group_bits',
			self.auto_permissions.c.group_bits,
		)
		if ('duration_longer_than') in filter:
			conditions.append(
				self.auto_permissions.c.duration > int(filter['duration_longer_than'])
			)
		if ('duration_shorter_than') in filter:
			conditions.append(
				self.auto_permissions.c.duration < int(filter['duration_shorter_than'])
			)
		conditions += time_cutoff_filter(
			filter,
			'valid_from',
			self.auto_permissions.c.valid_from_time,
		)
		conditions += time_cutoff_filter(
			filter,
			'valid_until',
			self.auto_permissions.c.valid_until_time,
		)
		conditions += id_filter(
			filter,
			'created_by_user_ids',
			self.auto_permissions.c.created_by_user_id,
		)

		statement = self.auto_permissions.select()
		if conditions:
			statement = statement.where(and_(*conditions))
		return statement

	def count_auto_permissions(self, filter={}):
		statement = self.prepare_auto_permissions_search_statement(filter)
		statement = statement.with_only_columns(
			[func.count(self.auto_permissions.c.id)]
		)
		return self.connection.execute(statement).fetchone()[0]

	def search_auto_permissions(
			self,
			filter={},
			sort='',
			order='',
			page=0,
			perpage=None
		):
		statement = self.prepare_auto_permissions_search_statement(filter)

		statement = sort_statement(
			statement,
			self.auto_permissions,
			sort,
			order,
			'creation_time',
			True,
			[
				'creation_time',
				'id',
			],
		)
		statement = paginate_statement(statement, page, perpage)

		result = self.connection.execute(statement).fetchall()
		if 0 == len(result):
			return IDCollection()

		user_ids = []
		for row in result:
			if row[self.auto_permissions.c.user_id]:
				user_ids.append(row[self.auto_permissions.c.user_id])
			if row[self.auto_permissions.c.created_by_user_id]:
				user_ids.append(row[self.auto_permissions.c.created_by_user_id])

		if user_ids:
			users = self.search_users(filter={'ids': user_ids})
		else:
			users = IDCollection()

		auto_permissions = IDCollection()
		for row in result:
			permission_group_bits = row[self.auto_permissions.c.group_bits]
			group_names = self.group_names_from_bits(permission_group_bits)
			auto_permission = AutoPermission(
				row[self.auto_permissions.c.id],
				creation_time=row[self.auto_permissions.c.creation_time],
				user_id=row[self.auto_permissions.c.user_id],
				scope=row[self.auto_permissions.c.scope],
				group_bits=permission_group_bits,
				group_names=group_names,
				duration=row[self.auto_permissions.c.duration],
				valid_from_time=row[self.auto_permissions.c.valid_from_time],
				valid_until_time=row[self.auto_permissions.c.valid_until_time],
				created_by_user_id=row[self.auto_permissions.c.created_by_user_id],
			)

			if auto_permission.user_id in users:
				auto_permission.user = users.get(
					auto_permission.user_id
				)

			if auto_permission.created_by_user_id in users:
				auto_permission.created_by_user = users.get(
					auto_permission.created_by_user_id
				)

			auto_permissions.add(auto_permission)
		return auto_permissions

	# manipulate auto permissions
	def create_auto_permission(self, **kwargs):
		auto_permission = AutoPermission(**kwargs)
		# preflight check for existing id
		if self.get_auto_permission(auto_permission.id_bytes):
			raise ValueError('Auto permission ID collision')
		self.connection.execute(
			self.auto_permissions.insert(),
			id=auto_permission.id_bytes,
			creation_time=int(auto_permission.creation_time),
			user_id=auto_permission.user_id_bytes,
			scope=str(auto_permission.scope),
			group_bits=int.from_bytes(auto_permission.group_bits, 'big'),
			duration=int(auto_permission.duration),
			valid_from_time=int(auto_permission.valid_from_time),
			valid_until_time=int(auto_permission.valid_until_time),
			created_by_user_id=auto_permission.created_by_user_id_bytes,
		)
		return auto_permission

	#TODO tests
	def update_auto_permission(self, id, **kwargs):
		auto_permission = AutoPermission(id=id, **kwargs)
		updates = {}
		if 'creation_time' in kwargs:
			updates['creation_time'] = int(auto_permission.creation_time)
		if 'user_id' in kwargs:
			updates['user_id'] = auto_permission.user_id_bytes
		if 'scope' in kwargs:
			updates['scope'] = str(auto_permission.scope)
		if 'group_bits' in kwargs:
			updates['group_bits'] = int.from_bytes(
				auto_permission.group_bits,
				'big',
			)
		if 'duration' in kwargs:
			updates['duration'] = int(auto_permission.duration)
		if 'valid_from_time' in kwargs:
			updates['valid_from_time'] = int(auto_permission.valid_from_time)
		if 'valid_until_time' in kwargs:
			updates['valid_until_time'] = int(auto_permission.valid_until_time)
		if 'created_by_user_id' in kwargs:
			updates['created_by_user_id'] = auto_permission.created_by_user_id_bytes
		if 0 == len(updates):
			return
		self.connection.execute(
			self.auto_permissions.update().values(**updates).where(
				self.auto_permissions.c.id == auto_permission.id_bytes
			)
		)

	def delete_auto_permission(self, id):
		id = get_id_bytes(id)
		self.connection.execute(
			self.auto_permissions.delete().where(
				self.auto_permissions.c.id == id,
			)
		)

	def delete_user_auto_permissions(self, user_id, scope=None):
		id = get_id_bytes(id)
		conditions = [self.auto_permissions.c.user_id == user_id]
		if scope:
			conditions.append(self.auto_permissions.c.scope == str(scope))
		self.connection.execute(
			self.auto_permissions.delete().where(and_(*conditions))
		)

	def sync_auto_permissions(self, ids=None, user_ids=None):
		current_time = time.time()
		filter = {
			'valid_from_before': current_time,
			'valid_until_after': current_time,
		}
		# check explicit None in case empty list has been passed in
		if None != ids:
			filter['ids'] = ids
		elif None != user_ids:
			filter['user_ids'] = user_ids

		auto_permissions = self.search_auto_permissions(filter=filter)

		# populate permissions for protected users
		protected_users = IDCollection()
		for auto_permission in auto_permissions.values():
			if auto_permission.user:
				user = auto_permission.user
				if user.protected:
					protected_users.add(user)
		if len(protected_users):
			self.populate_users_permissions(protected_users)

		new_permissions = {}
		for auto_permission in auto_permissions.values():
			if not auto_permission.user:
				continue
			user = auto_permission.user
			scope = auto_permission.scope
			if user.id_bytes not in new_permissions:
				new_permissions[user.id_bytes] = {}
			if scope not in new_permissions[user.id_bytes]:
				new_permissions[user.id_bytes][scope] = 0
				if user.protected:
					# for protected users start with existing permission
					if scope in user.permissions:
						new_permissions[user.id_bytes][scope] = int.from_bytes(
							user.permissions[scope].group_bits,
							'big',
						)
			new_permissions[user.id_bytes][scope] = self.combine_groups(
				bits=[
					new_permissions[user.id_bytes][scope],
					auto_permission.group_bits,
				]
			)

		# if we're only doing a sync for specific auto permissions then
		# only delete permissions for users associated with them
		if ids:
			# because user ids aren't known in advance and some auto permissions
			# may not have been returned in the search because they're expired
			# fetch auto permissions explicitly to find which user ids to delete
			# the permissions of
			specified_auto_permissions = self.search_auto_permissions(
				filter={'ids': ids},
			)
			user_ids = []
			for auto_permission in specified_auto_permissions.values():
				user_ids.append(auto_permission.user_id_bytes)
			if user_ids:
				self.delete_permissions(user_ids=user_ids)
		# if we're only doing a sync for specific users then
		# only delete permissions for those users
		elif user_ids:
			self.delete_permissions(user_ids=user_ids)
		# otherwise delete permissions for everyone while preserving protected
		else:
			self.delete_permissions()

		rows = []
		for user_id, scopes in new_permissions.items():
			for scope, group_bits in scopes.items():
				group_bits_int = int.from_bytes(group_bits, 'big')
				if user_id in protected_users:
					# update protected users with new permissions
					self.connection.execute(
						self.permissions.update().values(
							group_bits=group_bits_int
						).where(
							and_(
								self.permissions.c.user_id == user_id,
								self.permissions.c.scope == scope,
							)
						)
					)
				else:
					# otherwise insert new permissions
					rows.append({
						'id': uuid.uuid4().bytes,
						'user_id': user_id,
						'scope': scope,
						'group_bits': group_bits_int,
					})
		if not rows:
			return
		self.connection.execute(self.permissions.insert().values(rows))

	# delete user-related
	def delete_user_created_invites(self, user_id, preserve_redeemed=False):
		user_id = get_id_bytes(user_id)
		conditions = [self.invites.c.created_by_user_id == user_id]
		if preserve_redeemed:
			conditions.append(self.invites.c.redeem_time == 0)
		self.connection.execute(
			self.invites.delete().where(
				and_(*conditions)
			)
		)

	def delete_user_redeemed_invites(self, user_id):
		user_id = get_id_bytes(user_id)
		self.connection.execute(
			self.invites.delete().where(
				self.invites.c.redeemed_by_user_id == user_id
			)
		)

	def delete_user_sessions(self, user_id):
		user_id = get_id_bytes(user_id)
		self.connection.execute(
			self.sessions.delete().where(
				self.sessions.c.user_id == user_id
			)
		)

	def delete_user_permissions(self, user_id):
		user_id = get_id_bytes(user_id)
		self.connection.execute(
			self.permissions.delete().where(
				self.permissions.c.user_id == user_id
			)
		)

	def delete_user_auto_permissions(self, user_id):
		user_id = get_id_bytes(user_id)
		self.connection.execute(
			self.auto_permissions.delete().where(
				self.auto_permissions.c.user_id == user_id
			)
		)

	# anonymization
	def anonymize_user(self, user_id, new_user_id=None):
		user_id = get_id_bytes(user_id)
		self.update_user(user_id, name='', display='')

		if not new_user_id:
			new_user_id = uuid.uuid4().bytes

		# user
		self.connection.execute(
			self.users.update().values(id=new_user_id).where(
				self.users.c.id == user_id,
			)
		)
		# invites
		self.connection.execute(
			self.invites.update().values(created_by_user_id=new_user_id).where(
				self.invites.c.created_by_user_id == user_id,
			)
		)
		self.connection.execute(
			self.invites.update().values(redeemed_by_user_id=new_user_id).where(
				self.invites.c.redeemed_by_user_id == user_id,
			)
		)
		# sessions
		self.connection.execute(
			self.sessions.update().values(user_id=new_user_id).where(
				self.sessions.c.user_id == user_id,
			)
		)
		# authentications
		self.connection.execute(
			self.authentications.update().values(user_id=new_user_id).where(
				self.authentications.c.user_id == user_id,
			)
		)
		# permissions
		self.connection.execute(
			self.permissions.update().values(user_id=new_user_id).where(
				self.permissions.c.user_id == user_id,
			)
		)
		# auto permissions
		self.connection.execute(
			self.auto_permissions.update().values(user_id=new_user_id).where(
				self.auto_permissions.c.user_id == user_id,
			)
		)

		return new_user_id

	def anonymize_session_origins(self, sessions):
		for session in sessions.values():
			if 4 == session.remote_origin.version:
				# clear last 16 bits
				anonymized_origin = ip_address(
					int.from_bytes(session.remote_origin.packed, 'big')
					&~ 0xffff
				)
			elif 6 == session.remote_origin.version:
				# clear last 80 bits
				anonymized_origin = ip_address(
					int.from_bytes(session.remote_origin.packed, 'big')
					&~ 0xffffffffffffffffffff
				)
			else:
				raise ValueError('Encountered unknown IP version')
			self.connection.execute(
				self.sessions.update().values(
					remote_origin=anonymized_origin.packed
				).where(
					self.sessions.c.id == session.id_bytes
				)
			)
