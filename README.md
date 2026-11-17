# SRAM-sync
Docker container to synchronize iRODS users with accounts present in the SURF Research Access Management (SRAM) LDAP.

The container uses Python 3.14.

## User matching and reinstatement

Before making changes, the synchronizer resolves every LDAP user against iRODS. It first matches the lowercase LDAP
`uid` to a local iRODS username. If that username does not exist, it matches the LDAP `mail` to the iRODS `email` AVU,
ignoring case and surrounding whitespace. Repeated email AVUs on one account count as one match. With no match, it
creates a new account using the lowercase LDAP UID.

A returning user's unique email match reuses the existing iRODS account, retaining its username, home and permissions.
The synchronizer updates a changed `eduPersonUniqueID` if no other account owns the incoming ID. Ordinary UID matches
still require the existing unique ID to agree. Validated active accounts have all `pendingDeletionProcedure` and
`pendingSramInvite` AVUs removed, even when `DELETE_USERS=False`. Deletion checks and LDAP group memberships use the
resolved iRODS username rather than the new LDAP UID. LDAP remains authoritative for synchronized group memberships.

Only local, syncable `rodsuser` accounts can be recovered. Accounts marked `ldapSync=false` remain protected.
Ambiguous emails, protected matches, mismatched UID/email identities, conflicting unique IDs, or competing LDAP entries
stop the entire cycle before any writes. The conflicts are logged for manual review; accounts are never automatically
merged. A unique email match is treated as evidence that the returning LDAP user owns the existing account.

Omit `--commit` to preview matching, account creation, reinstatement, deletion marking and membership changes.
Dry runs do not modify accounts, AVUs, group memberships, passwords or temporary passwords.

### Check for duplicate email addresses

Run with an authenticated iRODS administrator session:

```bash
set -o pipefail
iquest --no-page '%s|%s|%s' \
  "SELECT META_USER_ATTR_VALUE, USER_NAME, USER_ZONE WHERE META_USER_ATTR_NAME = 'email' AND USER_TYPE <> 'rodsgroup'" |
awk -F '|' '
  NF == 3 {
    email = tolower($1)
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", email)
    account = $2 "#" $3
    if (email != "" && !seen[email SUBSEP account]++) {
      count[email]++
      accounts[email] = accounts[email] " " account
    }
  }
  END {
    for (email in count)
      if (count[email] > 1) print email ":" accounts[email]
  }'
```

This lists normalized email addresses shared by distinct `username#zone` accounts. No output means no duplicates among
the returned rows, provided `iquest` succeeds. The report covers all visible non-group account types and zones;
automatic recovery is restricted to syncable users in the configured local zone.

## Regression tests

With the requirements installed, run `python3 -m unittest -v test_sram_sync`.
The tests use mocked LDAP and iRODS services and do not connect to live servers.

## Running the container

The container is run based on the `docker-compose.yml` file in [docker-dev](https://github.com/MaastrichtUniversity/docker-dev)
An example compose file below.

**Note: this example file is not maintained**
```
  sram-sync:
    build: ./
    depends_on:
      - irods
      - ldap
    volumes:
      - /etc/localtime:/etc/localtime:ro
      - ./externals/sram-sync/:/opt/app
    environment:
      LOG_LEVEL: INFO
      IRODS_HOST: irods.dh.local
      IRODS_USER: rods
      IRODS_PASS: irods
      LDAP_USER: cn=admin,dc=datahubmaastricht,dc=nl
      LDAP_PASS: admin
      LDAP_HOST: ldap://ldap.dh.local
      LDAP_USERS_BASE_DN: ou=People,dc=flat,dc=datahubmaastricht,dc=nl
      LDAP_GROUPS_BASE_DN: ou=Groups,dc=flat,dc=datahubmaastricht,dc=nl
      LDAP_COS_BASE_DN:  dc=ordered,dc=datahubmaastricht,dc=nl
      DEFAULT_USER_PASSWORD: foobar
      LOGSTASH_TAGS: SRAMSYNC
      SYNC_USERS: "True"
      DELETE_USERS: "True"
      SYNC_GROUPS: "True"
      DELETE_GROUPS: "True"
    command: sram-sync.py --commit --scheduled
    networks:
      default:
```
