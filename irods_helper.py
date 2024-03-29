import logging
import os
import time
import ssl

from irods.exception import NetworkException
from irods.meta import iRODSMeta
from irods.session import iRODSSession

# Setup logging
log_level = os.environ["LOG_LEVEL"]
logging.basicConfig(level=logging.getLevelName(log_level), format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("root")


##########################################################
# multiple values will be lost!
def get_all_avus(irods_user):
    existing_avus = {}
    for item in irods_user.metadata.items():
        existing_avus[item.name] = item.value
    return existing_avus


##########################################################

# check if this is maybe more complicated then it has to be;
#   We can also use Python's item indexing syntax to perform the
#   equivalent of an "imeta set ...", e.g. overwriting all AVU's
#   with a name field of "key2" in a single update
def set_singular_avu(irods_user, avu_key, avu_value):
    changes = False
    if not avu_value:
        # this doesnt work: irods_user.metadata.remove( avu_key, None, None )
        for avu in irods_user.metadata.items():
            if avu.name == avu_key:
                irods_user.metadata.remove(avu)
                changes = True
    else:
        new_avu = iRODSMeta(avu_key, avu_value)
        all_old_metadata = irods_user.metadata.get_all(avu_key)
        if len(all_old_metadata) == 1 and all_old_metadata[0].value == avu_value:
            changes = False
        elif len(all_old_metadata) > 1:
            for avu in all_old_metadata:
                irods_user.metadata.remove(avu)
            irods_user.metadata[new_avu.name] = new_avu
            changes = True
        else:
            irods_user.metadata[new_avu.name] = new_avu
            changes = True
    return changes


##########################################################


def get_irods_connection(irods_host, irods_port, irods_user, irods_pass, irods_zone):
    max_tries = 5
    sleep_interval = 4
    ssl_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cafile=None, capath=None, cadata=None)
    ssl_settings = {
        "irods_client_server_negotiation": "request_server_negotiation",
        "irods_client_server_policy": os.environ["IRODS_CLIENT_SERVER_POLICY"],
        "irods_encryption_algorithm": "AES-256-CBC",
        "irods_encryption_key_size": 32,
        "irods_encryption_num_hash_rounds": 16,
        "irods_encryption_salt_size": 8,
        "ssl_context": ssl_context,
    }
    for n in range(max_tries + 1):
        try:
            # Setup iRODS connection
            sess = iRODSSession(
                host=irods_host, port=irods_port, user=irods_user, password=irods_pass, zone=irods_zone, **ssl_settings
            )
            return sess
        except NetworkException as e:
            logger.error(str(e))
            logger.info("retry {0} / {1}".format(n, max_tries))
            time.sleep(sleep_interval)
        if n >= max_tries:
            raise Exception("couldn't connect to iRods")
