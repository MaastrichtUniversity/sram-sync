import argparse
import logging
import os
import random
import re
import signal
import sys
import time
from datetime import datetime
from enum import Enum
import ldap

from irods.column import Criterion
from irods.exception import PycommandsException, iRODSException, UserDoesNotExist, UserGroupDoesNotExist, \
    CATALOG_ALREADY_HAS_ITEM_BY_THAT_NAME
from irods.models import User, UserGroup
from irods.user import iRODSUser, iRODSUserGroup

from irods_helper import get_all_avus, set_singular_avu, get_irods_connection
from ldap_helper import get_ldap_connection, for_ldap_entries_do, read_ldap_attribute

# Setup logging
log_level = os.environ['LOG_LEVEL']
logging.basicConfig(level=logging.getLevelName(log_level), format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger('root')

# Options config
DEFAULT_USER_PASSWORD = os.environ['DEFAULT_USER_PASSWORD']

SYNC_USERS = True if os.environ['SYNC_USERS'] == 'True' else False
DELETE_USERS = True if os.environ['DELETE_USERS'] == 'True' else False
DELETE_USERS_LIMIT = int(os.environ['DELETE_USERS_LIMIT'])
SYNC_GROUPS = True if os.environ['SYNC_GROUPS'] == 'True' else False
DELETE_GROUPS = True if os.environ['DELETE_GROUPS'] == 'True' else False


# LDAP config
LDAP_USER = os.environ['LDAP_USER']
LDAP_PASS = os.environ['LDAP_PASS']
LDAP_HOST = os.environ['LDAP_HOST']

#LDAP_GROUP = "Users"
LDAP_USERS_BASE_DN = os.environ['LDAP_USERS_BASE_DN']   
LDAP_GROUPS_BASE_DN = os.environ['LDAP_GROUPS_BASE_DN']

LDAP_SERVICE_PREFIX = "datahubmaastricht:"
LDAP_USERS_SEARCH_FILTER = "(objectClass=person)"      #"(objectClass=*)"
LDAP_GROUPS_SEARCH_FILTER = "(objectClass=posixGroup)" #"(objectClass=groupOfNames)"      
LDAP_GROUP_MEMBER_ATTR = 'memberUid' #will be sczMember!

LDAP_COS_BASE_DN =  os.environ['LDAP_COS_BASE_DN']  # dc=ordered,dc=datahubmaastricht,dc=nl
LDAP_COS_SEARCH_FILTER = "(objectClass=organization)"
LDAP_COS_ATTRIBUTES = ["o", "description","displayName"]       
LDAP_COS_SCOPE = ldap.SCOPE_SUBTREE  #SCOPE_BASE, SCOPE_SUBTREE, SCOPE_ONELEVEL

# iRODS config
IRODS_HOST = os.environ['IRODS_HOST']
IRODS_USER = os.environ['IRODS_USER']
IRODS_PASS = os.environ['IRODS_PASS']

IRODS_PORT = 1247
IRODS_ZONE = "nlmumc"

#irods groups and users with this AVU should not be synchronized (i.e. service-accounts, DH-ingest, ...)
LDAP_SYNC_AVU = 'LDAPsync'
#irods users who are not yet in SRAM should not be deleted
#To DO: but they could be synched! And the flag could be removed during the syncing, see UserAVU

##########################################################

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("commit", default=False, action='store_true', help="write any updates/changes to iRODS")
    parser.add_argument("scheduled", default=False, action='store_true', help="if set runs every few minutes")
    #parser.add_argument("print-ldap-info", default=False, action='store_true', help="print the internal model before writing to iRODS")

    return parser.parse_args()


##########################################################
# either a default password is given (via config.ini), or a random alpha string is generated
def create_new_irods_user_password():
    if DEFAULT_USER_PASSWORD == '':
        return DEFAULT_USER_PASSWORD
    chars = "abcdefghijklmnopqrstuvw"
    pwd_size = 20
    return ''.join((random.choice(chars)) for x in range(pwd_size))


##########################################################

class UserAVU(Enum):
    DISPLAY_NAME = 'displayName'
    EMAIL = "email"
    PENDING_INVITE = 'pendingSramInvite'
    
class GroupAVU(Enum):
    DISPLAY_NAME = 'displayName'
    DESCRIPTION = "description"

##########################################################

class LdapUser:
    LDAP_ATTRIBUTES = ['uid', 'mail', 'cn', 'displayName']  # all=*

    def __init__(self, uid, display_name, email):
        self.uid = uid
        self.display_name = display_name
        self.email = email
        self.irods_user = None

    def __repr__(self):
        return "User( uid:{}, displayName: {}, email: {}, iRodsUser: {})".format(self.uid, self.display_name,
                                                                                 self.email, self.irods_user)

    @classmethod
    def create_for_ldap_entry(cls, ldap_entry):
        uid = read_ldap_attribute(ldap_entry, 'uid')
        mail = read_ldap_attribute(ldap_entry, 'mail')
        cn = read_ldap_attribute(ldap_entry, 'cn')
        #display_name = read_ldap_attribute(ldap_entry, 'displayName')
        # TO DO: here we could decided weather to use the cn or uid as displayName...
        return LdapUser(uid, cn, mail)

    # simply write the model user to irods,
    # set password and AVUs for existing attributes
    def create_new_user(self, irods_session, dry_run):
        if dry_run:
            return
        logger.info("* Create a new irods user: %s" % self.uid)
        new_irods_user = irods_session.users.create(self.uid, 'rodsuser')
        if self.email: new_irods_user.metadata.add(UserAVU.EMAIL.value, self.email)
        if self.display_name: new_irods_user.metadata.add(UserAVU.DISPLAY_NAME.value, self.display_name)
        password = create_new_irods_user_password()
        irods_session.users.modify(self.uid, 'password', password)
        self.irods_user = new_irods_user

        # TO DO: is this the correct place? Any other must have groups that I'm missing?
        # Add the user to the group DH-ingest (= ensures that user is able to create and ingest dropzones)
        add_user_to_group(irods_session, "DH-ingest", self.uid)

        return self.irods_user

    def update_existing_user(self, irods_session, dry_run):
        if dry_run:
            return self.irods_user
        logger.debug("-- changing existing irods user:" + self.uid)
        try:
            # read current AVUs and change if needed
            existing_avus = get_all_avus(self.irods_user)
            logger.debug("-- existing AVUs BEFORE: " + str(existing_avus))
            # careful: because the list of existing AVUs is not updated changing a key multiple times will lead to
            # strange behavior!
            if set_singular_avu(self.irods_user, UserAVU.EMAIL.value, self.email):
                logger.info( "-- user {} updated AVU: {} {}".format( self.uid, UserAVU.EMAIL.value, self.email ) )
            if set_singular_avu(self.irods_user, UserAVU.DISPLAY_NAME.value, self.display_name):
                logger.info( "-- user {} updated AVU: {} {}".format( self.uid, UserAVU.DISPLAY_NAME.value, self.display_name ) )
            if set_singular_avu(self.irods_user, UserAVU.PENDING_INVITE.value, None):
                logger.info( "-- user {} updated AVU: {} {}".format( self.uid, UserAVU.PENDING_INVITE.value, None ) )
        except iRODSException as error:
            logger.error("-- error changing AVUs" + str(error))
        existing_avus = get_all_avus(self.irods_user)
        logger.debug("-- existing AVUs AFTER: " + str(existing_avus))
        return self.irods_user

    def sync_to_irods(self, irods_session, dry_run, created, updated, failed):
        # Check if user exists
        exists_username = True
        try:        
            # Lower case the uid (email address) from UM LDAP
            # There are users with upper case character in their LDAP uid
            self.irods_user = irods_session.users.get(self.uid.lower() )
        except UserDoesNotExist:
            exists_username = False
        # If user does not exists create user
        if not exists_username:
            try:
                if not dry_run:
                    self.irods_user = self.create_new_user(irods_session, dry_run)
                logger.info("-- User: " + self.uid + " created")
                if created:
                    created()
            except (PycommandsException, PycommandsException) as e:
                logger.error("-- User creation error: " + str(e))
                if failed:
                    failed()
        else:
            try:
                if not dry_run:
                    self.irods_user = self.update_existing_user(irods_session, dry_run)
                logger.debug("-- User: " + self.uid + " updated")
                if updated:
                    updated()
            except (PycommandsException, iRODSException ) as e:
                logger.error("-- User update error: " + str(e))
                if failed:
                    failed()


##########################################################
class LdapGroup:
    LDAP_ATTRIBUTES = ['*']  # all=*
    AVU_KEYS = []

    def __init__(self, group_name, member_uids=[]):
        self.group_name = group_name
        self.member_uids = member_uids
        self.irods_group = None
        self.display_name = None
        self.description = None

    def __repr__(self):
        return "Group( group_name:{}, member_uids: {},  irods_group: {}, display_name: {})".format(self.group_name, self.member_uids,
                                                                                 self.irods_group, self.displayName)

    @classmethod
    # b'uid=p.vanschayck@maastrichtuniversity.nl,ou=users,dc=datahubmaastricht,dc=nl'
    def get_group_member_uids(cls, user_dn):
        LDAP_EMPTY_USER = "cn=empty-membership-placeholder"
        dn = user_dn.decode("utf-8").strip()
        if dn == LDAP_EMPTY_USER:
            return None
        user_dict = dict(re.findall(r'([\w]+)=([\w\.@]+)', dn))
        return user_dict.get('uid', None)
#---
    @classmethod
    def create_for_ldap_entry(cls, ldap_entry):
        group_name = read_ldap_attribute(ldap_entry, 'cn')
        # get us an array of all member-attributes, which contains
        # DNs: [ b'cn=empty-membership-placeholder',  b'uid=p.vanschayck@maastrichtuniversity.nl,ou=users,dc=datahubmaastricht,dc=nl', ...]
        group_member_dns = ldap_entry.get( LDAP_GROUP_MEMBER_ATTR, [b""])
        group_member_uids = list(
            filter(lambda x: x is not None, map(LdapGroup.get_group_member_uids, group_member_dns)))
        return LdapGroup(group_name, group_member_uids)
#---      
    def create_new_group(self, irods_session, dry_run):
       if dry_run:
          return
       new_group = irods_session.user_groups.create(self.group_name)
       if self.display_name: 
          new_group.metadata.add(GroupAVU.DISPLAY_NAME.value, self.display_name)
       if self.description: 
          new_group.metadata.add(GroupAVU.DESCRIPTION.value, self.description)
       #should we add a reference to the CO as AVU?
       return self.irods_group
#---
    def update_existing_group(self, irods_session, dry_run):
       if dry_run:
            return self.irods_user
       logger.debug("-- changing existing irods group: {}".format( self.group_name ) )
       try:
            # read current AVUs and change if needed
            existing_avus = get_all_avus(self.irods_group)
            logger.debug("-- existing AVUs BEFORE: " + str(existing_avus))
            # careful: because the list of existing AVUs is not updated changing a key multiple times will lead to
            # strange behavior!     
            if set_singular_avu(self.irods_group, GroupAVU.DESCRIPTION.value, self.description):
                logger.info( "-- group {} updated AVU: {} {}".format( self.group_name, GroupAVU.DESCRIPTION.value, self.description ) )
            if set_singular_avu(self.irods_group, GroupAVU.DISPLAY_NAME.value, self.display_name):
                logger.info( "-- group {} updated AVU: {} {}".format( self.group_name, GroupAVU.DISPLAY_NAME.value, self.display_name ) )
       except iRODSException as error:
            logger.error("-- error changing AVUs" + str(error))
       existing_avus = get_all_avus(self.irods_group)
       logger.debug("-- existing AVUs AFTER: " + str(existing_avus))
       return self.irods_group
#---
    def sync_to_irods(self, irods_session, dry_run, created, updated, failed):
        # Check if the group exists
        exists_group = True
        try:
            self.irods_group = irods_session.user_groups.get(self.group_name)
        except UserGroupDoesNotExist:
            exists_group = False

        if not exists_group:
            try:
                if not dry_run:
                    #self.irods_group = sess.user_groups.create(self.group_name)
                    self.irods_group = self.create_new_group( irods_session, dry_run )
                logger.info("-- Group %s created" % self.group_name)
                if created:
                    created()      
            except (PycommandsException, iRODSException ) as e:
                logger.error("-- Group {} Creation error: {}".format( self.group_name, str(e) ) )
                if failed:
                    failed()
        else:
        	  try:
        	     if not dry_run:
        	        self.irods_group = self.update_existing_group(irods_session, dry_run)
        	     logger.debug("-- Group: " + self.group_name + " updated")
        	     if updated:
        	        updated()
        	  except (PycommandsException, iRODSException ) as e:
        	     logger.error("-- User update error: " + str(e))
        	     if failed:
        	        failed()
        return self.irods_group

    @classmethod
    def remove_group_from_irods(cls, sess, group_name):
        sess.users.remove(group_name, user_zone=IRODS_ZONE)


##########################################################
##########################################################
##########################################################


def syncable_irods_users(sess):
    irods_user_names_set = set()
    # filter only rodsusers, filter the special users, check wich one are not in the LDAP list
    query = sess.query(User.name, User.id, User.type).filter(
        Criterion('=', User.type, 'rodsuser'))
    n = 0
    for result in query:
        n = n + 1
#       if not result[User.name] in unsynced_users:     
        irodsUser = sess.users.get(result[User.name])
        syncAVUs = irodsUser.metadata.get_all( LDAP_SYNC_AVU )
        if not syncAVUs:
            irods_user_names_set.add(result[User.name])
        elif (len(syncAVUs) == 1) and (syncAVUs[0].value == "true"):
            irods_user_names_set.add(result[User.name])
        elif (len(syncAVUs) == 1) and (syncAVUs[0].value == "false"):
            logger.debug( "AVU ldapSync=false found for user: {}".format( irodsUser.name ))
            continue
        else:
            logger.error( "found unexpected number of AVUs for key ldapSync and user: {} {}".format( irodsUser.name, len(syncAVUs) ))

    logger.debug("iRods users found: {} (allowed for synchronization: {})".format(n, len(irods_user_names_set)))
    return irods_user_names_set


##########################################################

# get all the relevant attributes of all users in LDAP, returns an array with dictionaries
def get_users_from_ldap(l):
    return for_ldap_entries_do(l, LDAP_USERS_BASE_DN, LDAP_USERS_SEARCH_FILTER, LdapUser.LDAP_ATTRIBUTES,
                               LdapUser.create_for_ldap_entry)


##########################################################
def remove_obsolete_irods_users(sess, ldap_users, irods_users):
    logger.info("* Deleting obsolete irods users...")
    deletion_candidates = irods_users.copy()
    for ldap_user in ldap_users:
        deletion_candidates.discard(ldap_user.uid)

    number_deletions = len(deletion_candidates)
    logger.info("-- identified %d obsolete irods users for deletion" % number_deletions)

    if number_deletions >= DELETE_USERS_LIMIT:
        logger.error("-- The limit of deletions (%d) in one synchronization have been reached. "
                     "Deletions aborted" % number_deletions)
    else:
        for uid in deletion_candidates:
            user = sess.users.get(uid)
            avus = get_all_avus(user)
            if UserAVU.PENDING_INVITE.value in avus:
               logger.info("-- won't delete user {} since its marked as invitation pending.".format(uid))
            else:
               logger.info("-- deleting user: {}".format(uid))
               user.remove()


##########################################################

def sync_ldap_users_to_irods(ldap, irods, dry_run):
    logger.info("Syncing users to iRods:")

    ldap_users = get_users_from_ldap(ldap)
    logger.info("* LDAP users found: %d" % len(ldap_users))

    irods_users = syncable_irods_users(irods)

    # remove obsolete users from irods
    if not dry_run and DELETE_USERS:
        remove_obsolete_irods_users(irods, ldap_users, irods_users)

    # Loop over ldap users and create or update as necessary
    logger.debug("* Syncing {} found LDAP entries to iRods:".format( len(ldap_users) ) )
    n = 0
    for user in ldap_users:
        n = n + 1
        # Print username
        logger.debug("-- syncing LDAP user {}/{}: {}".format(n, len(ldap_users), user.uid))

        if dry_run or (not SYNC_USERS):
            logger.info("-- syncing of users not permitted. User {} will no be changed/created".format(user.uid))
            continue

        user.sync_to_irods(irods, dry_run, None, None, None)

    return ldap_users


##########################################################

def remove_obsolete_irods_groups(sess, ldap_group_names, irods_group_names):
    logger.info("* Deleting obsolete irods groups...")
    deletion_candidates = set()
    for irods_group in irods_group_names:
        if irods_group not in ldap_group_names:
            deletion_candidates.add(irods_group)
    logger.info("-- identified %d obsolete irods groups for deletion" % len(deletion_candidates))

    for group_name in deletion_candidates:
        logger.info("-- deleting group: {}".format(group_name))
        LdapGroup.remove_group_from_irods(sess, group_name)


##########################################################

def get_ldap_co( ldap_entry ):
    o = read_ldap_attribute( ldap_entry, 'o') 
    #potentially dangerous!        
    #logger.info( o )
    if ':' in o: 
       key = o.split(":")[1]
       displayName = read_ldap_attribute( ldap_entry,'displayName')   
       description = read_ldap_attribute( ldap_entry,'description')
       return { "key": key, "o": o, "description": description, "display_name": displayName }
    else:   
       #this could happen when searching for scope_subtree, then the 'ordered" organization is found, which doesnt comply with the naming schema
       return { "key": o, "o": o, "description": None, "display_name": None }

def get_ldap_cos(l):
   result = dict()
   ldap_cos = for_ldap_entries_do( l, LDAP_COS_BASE_DN, LDAP_COS_SEARCH_FILTER, LDAP_COS_ATTRIBUTES, get_ldap_co, scope=LDAP_COS_SCOPE )
   for co in ldap_cos:   
      result[ co[ 'key' ] ] = co
   return result

##########################################################
# get all groups from LDAP
def get_ldap_groups(l, group_key_2_co ):
	 #get the groups
    group_name_2_groups = dict()
    ldap_groups = for_ldap_entries_do(l, LDAP_GROUPS_BASE_DN, LDAP_GROUPS_SEARCH_FILTER, ["*"],
                                      LdapGroup.create_for_ldap_entry)
                                                         
    for group in ldap_groups:
    	#dangerous: by 
    	co_key = group.group_name.split(":")[0]
    	group_name_2_groups[group.group_name] = group
    
    return group_name_2_groups


##########################################################
def add_user_to_group(sess, group_name, user_name):
    irods_group = sess.user_groups.get(group_name)
    try:
        irods_group.addmember(user_name)
        logger.info("-- User: " + user_name + " added to group " + group_name)
    except CATALOG_ALREADY_HAS_ITEM_BY_THAT_NAME:
        logger.info("-- User {} already in group {} ".format(user_name, group_name))
    except (PycommandsException, iRODSException ) as e:
        logger.error("-- could not add user {} to group {}. '{}'".format(user_name, group_name, e))


########################################################## 
def remove_user_from_group(sess, group_name, user_name):
    irods_group = sess.user_groups.get(group_name)
    try:
        irods_group.removemember(user_name)
        logger.info("-- User: " + user_name + " removed from group " + group_name)
    # TO DO: This should not catch all exceptions!
    except (PycommandsException, iRODSException ) as e:
        logger.error("-- could not remove user {} from group {}. '{}'".format(user_name, group_name, e))

##########################################################

def get_syncable_irods_groups(sess):
    irods_group_names_set = set()
    # filter only rodsgroups,
    query = sess.query(User.name, User.id, User.type).filter(
        Criterion('=', User.type, 'rodsgroup'))
    n = 0
    for result in query:
        n = n + 1
#       if not result[User.name] in unsynced_users:     
        irodsGroup = sess.users.get(result[User.name])
        syncAVUs = irodsGroup.metadata.get_all( LDAP_SYNC_AVU )
        if not syncAVUs:
            irods_group_names_set.add( irodsGroup.name )
        elif (len(syncAVUs) == 1) and (syncAVUs[0].value == "true"):
            irods_group_names_set.add( irodsGroup.name )
        elif (len(syncAVUs) == 1) and (syncAVUs[0].value == "false"):
            logger.debug( "AVU ldapSync=false found for group: {}".format( irodsGroup.name ))
            continue
        else:
            logger.error( "found unexpected number of AVUs for key ldapSync and group: {} {}".format( irodsGroup.name, len(syncAVUs) ))

    logger.debug("iRods groups found: {} (allowed for synchronization: {})".format(n, len(irods_group_names_set)))
    return irods_group_names_set

##########################################################

def sync_ldap_groups_to_irods(ldap, irods, dry_run):
    logger.info("Syncing groups to irods:")

    group_key_2_co = get_ldap_cos(ldap)
    logger.debug("* LDAP cos found: {}".format( len(group_key_2_co) ) )
    group_name_2_group = get_ldap_groups(ldap, group_key_2_co)
    logger.debug("* LDAP groups found: {}".format( len(group_name_2_group) ) )

    syncable_irods_groups = get_syncable_irods_groups( irods )

    if not dry_run and DELETE_GROUPS:
        remove_obsolete_irods_groups(irods, group_name_2_group.keys(), syncable_irods_groups)

    n = 0
    for (group_name, group) in group_name_2_group.items():
        n = n + 1
        logger.debug("-- syncing LDAP group {}/{}: {}".format(n, len(group_name_2_group), group_name))
        #enhance groups with co information
        if group_name in group_key_2_co:
        	   co = group_key_2_co[ group_name ]
        	   group.display_name = co[ 'display_name' ]
        	   group.description = co[ 'description' ]
        if not dry_run:
            group.sync_to_irods(irods, dry_run, None, None, None)
        else:
            logger.info("-- syncing of groups not permitted. Group {} will no be changed/created".format(group_name))

    return group_name_2_group


##########################################################
def diff_member_lists(ldap_members, irods_members):
    if not bool(irods_members):
        return set(), ldap_members, set()
    if not bool(ldap_members):
        return set(), set(), irods_members
    stay = set(filter(lambda x: x in irods_members, ldap_members))
    add = set(filter(lambda x: x not in irods_members, ldap_members))
    remove = set(filter(lambda x: x not in ldap_members, irods_members))
    return stay, add, remove


##########################################################
def sync_group_memberships(irods, ldap_groups, dry_run):
    logger.info("Syncing group members to irods:")

    # create a mapping of irods group names to the member uids
    irods_groups_2_users = dict()

    #original code copied from python-irodsclient to create group-memers mapping:
    #   grp_usr_mapping = [ (iRODSUserGroup( irods.user_groups, result), iRODSUser(irods.users, result)) for result in irods.query(UserGroup,User) ]
    #   rp_usr_mapping2 = [ (x,y) for x,y in grp_usr_mapping if x.id != y.id ]
    #was always missing one member!
    #irods_groups_query = irods.query(UserGroup).filter(User.type == 'rodsgroup')
    syncable_irods_groups = get_syncable_irods_groups( irods )      
    
    
    for groupName in syncable_irods_groups:
        #userGroup = iRODSUserGroup( irods.user_groups, group )
        userGroup = irods.user_groups.get(groupName)
        member_names = set( user.name for user in userGroup.members )
        logger.debug("-- irods-group: {}, members: {}".format( groupName, member_names ) )
        irods_groups_2_users[groupName] = member_names

    # check each LDAP Group against each irodsGroup
    n = 0
    for (group_name, group) in ldap_groups.items():
        if userGroup.name not in syncable_irods_groups:
           continue
        n = n + 1
        logger.info("* Syncing memberships for group {}...".format(group_name))
        irods_member_list = irods_groups_2_users.get(group_name, set())
        stay, add, remove = diff_member_lists(group.member_uids, irods_member_list)
        logger.info("-- memberships for group {}: {} same, {} added, {} removed".format(group_name, len(stay), len(add),
                                                                                     len(remove)))

        if not dry_run:
            for uid in add:
                add_user_to_group(irods, group_name, uid)

            for uid in remove:
                remove_user_from_group(irods, group_name, uid)


##########################################################


def main(dry_run):
    start_time = datetime.now()
    logger.info("SRAM-SYNC started at: {}".format(start_time))

    if dry_run:
        logger.info("EXECUTING SCRIPT IN DRY MODE! No changes will be made to iCAT.")

    ldap = get_ldap_connection(LDAP_HOST, LDAP_USER, LDAP_PASS)
    irods = get_irods_connection(IRODS_HOST, IRODS_PORT, IRODS_USER, IRODS_PASS, IRODS_ZONE)

    ldap_groups = None
    if SYNC_USERS:
        sync_ldap_users_to_irods(ldap, irods, dry_run)

    if SYNC_GROUPS:
        ldap_groups = sync_ldap_groups_to_irods(ldap, irods, dry_run)

    if SYNC_USERS and SYNC_GROUPS:
        sync_group_memberships(irods, ldap_groups, dry_run)

    end_time = datetime.now()
    logger.info("SRAM-SYNC finished at: {} (took {} sec)\n".format(end_time, (end_time - start_time).total_seconds()))

    return 0


##########################################################


def sigterm_handler(_signal, _stack_frame):
    sys.exit(0)


if __name__ == "__main__":
    # Handle the SIGTERM signal from Docker
    signal.signal(signal.SIGTERM, sigterm_handler)
    settings = parse_arguments()

    try:
        exit_code = main(not settings.commit)
        if settings.scheduled:
            while True:
                time.sleep(5 * 60)
                main(not settings.commit)
        sys.exit(exit_code)
    finally:
        # Perform any clean up of connections on closing here
        logger.info("Exiting")
