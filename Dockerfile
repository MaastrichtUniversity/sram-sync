FROM python:3.6

WORKDIR /opt/app

# Conditionally trust the custom DataHub *Dev/Test-only* Certificate Authority (CA) for iRODS-SSL-connections
ADD ssl-dev/test_only_dev_irods_dh_ca_cert.pem /tmp/test_only_dev_irods_dh_ca_cert.pem
ARG SSL_ENV
# Note: Python docker image is Debian-based. So, 'dash' as /bin/sh.
#       Strict POSIX-compliant.
RUN if [ "${SSL_ENV}" = "dev" ] || [ "${SSL_ENV}" = "DEV" ]; then \
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
    libssl-dev

# Python requirements
ADD requirements.txt /opt
RUN pip install -r /opt/requirements.txt

# Entry point
ADD bootstrap.sh /opt
RUN chmod +x /opt/bootstrap.sh

VOLUME ["/input", "/output"]
ENTRYPOINT [ "/opt/bootstrap.sh" ]