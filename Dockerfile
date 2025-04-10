FROM python:3.11.11

WORKDIR /opt/app

# Conditionally trust the custom DataHub *Dev/Test-only* Certificate Authority (CA) for iRODS-SSL-connections
ADD ssl-dev/test_only_dev_irods_dh_ca_cert.pem /tmp/test_only_dev_irods_dh_ca_cert.pem
ARG SSL_ENV
# Note: Python docker image is Debian-based. So, 'dash' as /bin/sh.
#       Strict POSIX-compliant.
RUN if [ $SSL_ENV != "acc" ] && [ $SSL_ENV != "prod" ]; then \
        echo "Adding custom DataHub iRODS-CA-certificate to the CA-rootstore (FOR DEV & TEST ONLY!)..." ; \
        cp /tmp/test_only_dev_irods_dh_ca_cert.pem /usr/local/share/ca-certificates/test_only_dev_irods_dh_ca_cert.crt ; \
        update-ca-certificates ; \
    else \
        echo "Not in dev environment: Skipping update of the CA-rootstore" ; \
    fi

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    libldap2-dev \
    libsasl2-dev \
    libssl-dev \
    libldap-common

# Python requirements
ADD requirements.txt /opt
RUN pip install -r /opt/requirements.txt

# /dh_is_ready.sh will print READY if sram-sync has run at least once
ADD dh_is_ready.sh /dh_is_ready.sh

# This keeps track of the amount of runs, which is used for the development is_ready.sh script
RUN touch /var/run/sram-syncs
RUN chmod a+w /var/run/sram-syncs

# Entry point
ADD bootstrap.sh /opt
RUN chmod +x /opt/bootstrap.sh

VOLUME ["/input", "/output"]
ENTRYPOINT [ "/opt/bootstrap.sh" ]
