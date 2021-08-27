# SRAM-sync
Docker container to synchronize iRODS users with accounts present in the SURF Research Access Management (SRAM) LDAP.

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