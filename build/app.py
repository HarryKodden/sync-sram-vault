# app.py

import os
import logging

LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()
LOG_LEVEL = 'DEBUG'
logging.basicConfig(
    encoding='utf-8',
    level=LOG_LEVEL,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

logging.basicConfig(encoding='utf-8', level=LOG_LEVEL)

from flask import Flask

app = Flask(__name__)

from vault import VAULT
from ldap import LDAP

@app.route('/sync')
def sync():
    logging.info("Start synchronisation...")

    services = {}

    with LDAP() as my_ldap:
        for g in my_ldap.groups.keys():
            attributes = my_ldap.groups[g].get('attributes', {})
            displayName = attributes.get('displayName', [''])[0]
            members = attributes.get('member', [])

            if displayName.lower().startswith('vault:'):
                services[g] = members
                    
    logging.info("Services: {}".format(services))

    # services = {}

    with VAULT(
        os.environ.get('VAULT_ADDR', 'http://localhost:8200'),
        os.environ.get('VAULT_TOKEN', '?')
    ) as my_vault:

        # my_vault.delete_all_approles()

        logging.debug("Existing services: {}".format(my_vault))

        # Deletions of services...
        for service in list(set(my_vault.services) - set(services)):

            for owner in my_vault.secrets(service):
                    my_vault.delete(service, owner)

            my_vault.delete(service)

        for service in services:

            secrets = my_vault.secrets(service) if service in my_vault.services else []

            # Deletions of secrets...
            for owner in list(set(secrets) - set(services[service])):
                my_vault.delete(service, owner)

            # Check for new owners...
            for owner in list(set(services[service]) - set(secrets)):
                my_vault.password(service, owner)

            # Validate Service impersonating...
            (role_id, role_secret) = my_vault.approle(service)

            for owner in services[service]:

                wrapped_token = my_vault.wrap_token(service, owner)
                if wrapped_token:
                    vault_token = my_vault.unwrap_token(role_id, role_secret, wrapped_token)
                    if vault_token:
                        secret = my_vault.read(vault_token, service, owner)
                        if secret:
                            logging.info("Service: {}, User: {}, Secret: {}".format(service, owner, secret))
                        else:
                            logging.error("Error reading secret for Service: {}, User: {}".format(service, owner))
                    else:
                        logging.error("Error unwrapping token for role: {}".format(role_id))
                else:
                    logging.error("Error wrapping token for servie: {}, user: {}".format(service, owner))

    logging.info("Done !")
    return services

if __name__ == '__main__':
    app.run(debug=(LOG_LEVEL == "DEBUG"))
