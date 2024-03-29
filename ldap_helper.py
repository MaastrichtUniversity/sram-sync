import logging
import os
import ldap

# Setup logging
log_level = os.environ["LOG_LEVEL"]
logging.basicConfig(level=logging.getLevelName(log_level), format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("root")


##########################################################


def read_ldap_attribute(ldap_entry, key):
    return ldap_entry.get(key, [b""])[0].decode("utf-8").strip()


##########################################################


def for_ldap_entries_do(c, base_dn, search_filter, retrieve_attributes, callback, scope=ldap.SCOPE_SUBTREE):
    return_array = []
    # search_scope = ldap.SCOPE_SUBTREE
    # if scope: search_scope = scope

    # Perform the LDAP search
    id = c.search(base_dn, scope, search_filter, retrieve_attributes)
    # all = 1
    # If all is 0, search entries will be returned one at a time as they come in, via separate calls to result().
    # If all is 1, the search response will be returned in its entirety, i.e. after all entries and the final search
    # result have been received.
    result_type, result = c.result(id, all=0)
    while result:
        if result[0] and len(result[0]) == 2:
            entry = result[0][1]
            if entry:
                function_result = callback(entry)
                return_array.append(function_result)
        result_type, result = c.result(id, all=0)
    return return_array


##########################################################


def get_ldap_connection(ldap_host, ldap_user, ldap_pass):
    # Setup LDAP connection
    c = ldap.initialize(ldap_host)
    c.protocol_version = ldap.VERSION3
    c.simple_bind_s(ldap_user, ldap_pass)
    return c
