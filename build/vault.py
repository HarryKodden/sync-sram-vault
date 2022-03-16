# vault.py
import os
import logging
import uuid
import json

from api import API

SECRET_ROOT = 'v1/secret'
SERVICES = "services"
SECRET_DATA_PATH = SECRET_ROOT+'/data/'+SERVICES
SECRET_META_PATH = SECRET_ROOT+'/metadata/'+SERVICES
SECRET_DESTROY_PATH = SECRET_ROOT+'/destroy/'+SERVICES


class VAULT(API):

    headers = None

    def __init__(self, vault_addr, vault_token):
        self.headers = {
            "X-Vault-Token": vault_token,
            "Content-Type": "application/json"
        } 
        super().__init__(vault_addr)

    @property
    def services(self):
        return self.secrets()

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception_value, traceback):
        pass

    def __repr__(self):
        return json.dumps(self.json(), indent=4, sort_keys=True)

    def json(self):
        return {
            'services': self.services
        }

    def api(self, uri, method='GET', **kwargs):
        if not 'headers' in kwargs:
            kwargs['headers'] = self.headers

        (rc, data) = super().api(
            uri,
            method=method,
            **kwargs
        )

        logging.debug(f"DATA: {data}...")
        return (rc, data)


    def approle(self, service):

        if service not in self.services:
            logging.error("Cannot create AppRole for non existing service: {}".format(service))
            return (None, None)

        self.api(
            "v1/sys/auth/approle",
            method="POST", 
            json={"type": "approle"}
        )

#       app_role = str(uuid.uuid4())
        app_role = service.replace(' ','-').lower()

        (rc, _) = self.api(
            "v1/auth/approle/role/{}".format(app_role),
            method="POST", 
            json={"policies": "default"}
        )

        if rc == 204:

            (rc, data) = self.api(
                "v1/auth/approle/role/{}/role-id".format(app_role)
            )

            if rc == 200:

                role_id = data['data']['role_id']

                (rc, data) = self.api(
                    "v1/auth/approle/role/{}/secret-id".format(app_role),
                    method="POST"
                )

                if rc == 200:
                    secret_id = data['data']['secret_id']

                    return (role_id, secret_id)
                else:
                    logging.error("Can not retrieve Secret Id for service: {}, error: {}".format(service, rc))
            else:
                logging.error("Can not retrieve Role Id for service: {}, error: {}".format(service, rc))
        else:
            logging.error("Cannot create AppRole for service: {}, error: {}".format(service, rc))

        return (None, None)


    def wrap_token(self, service, username):
        wrap_header = {
            'X-Vault-Wrap-TTL': '120'
        }

        (rc, data) = self.api(
            "v1/auth/token/create",
            method="POST",
            headers={ **wrap_header, **self.headers },
            json={"policies": "{}-{}".format(service, username)}
        )

        if rc == 200:
            return data['wrap_info']['token']

        logging.error("Cannot wrap token for service: {}, error: {}, {}".format(service, rc, data))

        return None

    def unwrap_token(self, role_id, secret_id, wrapped_token):

        (rc, data) = self.api(
            "v1/auth/approle/login",
            method="POST", 
            headers={
                "Content-Type": "application/json"
            },
            json={
                "role_id": role_id,
                "secret_id": secret_id
            }
        )

        if rc == 200:

            (rc, data) = self.api(
                "v1/sys/wrapping/unwrap",
                method="POST", 
                headers={
                    "X-Vault-Token": data['auth']['client_token'],
                    "Content-Type": "application/json"
                },
                json={
                    "token": wrapped_token
                }
            )
            if rc == 200:
                return data['auth']['client_token']
            else:
                logging.error("Cannot unwrap token for role_id: {}, error: {}".format(role_id, rc))
        else:
            logging.error("Cannot login with role_id: {}, error: {}".format(role_id, rc))

        return None


    def read(self, vault_token, service, username):
        (rc, data) = self.api(
            'v1/secret/data/services/{}/{}'.format(service, username),
            headers={
                "X-Vault-Token": vault_token,
                "Content-Type": "application/json"
            }
        )

        if rc == 200:
            return data['data']

        logging.error("Cannot read secret service: {}, user: {}, error: {}".format(service, username, rc))

        return None


    def delete_all_approles(self):
        (rc, data) = self.api(
            'v1/auth/approle/role',
            method='LIST'
        )

        if rc == 200:
            for a in data['data']['keys']:
                self.api(
                    'v1/auth/approle/role/{}'.format(a),
                    method='DELETE'
                )

    def delete(self, service, username=None):

        def delete_versions(versions):
            logging.debug("Deleting versions: {}".format(versions))
    
            path = "{}/{}/{}".format(SECRET_DESTROY_PATH, service, username)

            (rc, _) = self.api(path, method="POST", json=versions)
            if rc != 204:
                logging.error("RC on delete secret: {}".format(rc))

        path = "{}/{}".format(SECRET_META_PATH, service)

        if username:
            path += '/{}'.format(username)

            (rc, data) = self.api(path)
            if rc == 200:
                delete_versions({ 'versions': [ i for i in data['data']['versions'].keys() ] })

            (rc, _) = self.api(
                "v1/sys/policy/{}-{}".format(service, username),
                method="DELETE"
            )
            if rc != 204:
                logging.error("Error deleting policy for service: {}, user: {}, error: {}".format(service, username, rc)) 

        (rc, _) = self.api(path, method="DELETE")
        if rc != 204:
            logging.error("Error deleting secret for service: {}, user: {}, error: {}".format(service, username, rc)) 

 
        logging.debug("Done deleting secret !")


    def create(self, service, username, password):

        self.delete(service, username)

        (rc, _) = self.api(
            "{}/{}/{}".format(SECRET_DATA_PATH, service, username),
            method="POST", 
            json={ 'data': {'password': password }}
        )
        
        if rc != 200:
            logging.error("RC on create secret: {}".format(rc))

        (rc, _) = self.api(
            "v1/sys/policy/{}-{}".format(service, username),
            method="PUT", 
            json={ 
                "policy": "path \"/secret/data/services/{}/{}\" {{ capabilities = [\"read\"] }}".format(service, username)
            }
        )
        if rc != 204:
            logging.error("Error creating policy for service: {}, user: {}, error: {}".format(service, username, rc)) 


    def secrets(self, service=None):

        path = "{}".format(SECRET_META_PATH)

        if service:
            path += '/{}'.format(service)

        (rc, data) = self.api(
            path,
            method="LIST"
        )
        
        if rc != 200:
            logging.error("No entries found ! ({})".format(path))
        else:
            try:
                keys = data['data']['keys']
                return [k.rstrip('/') for k in keys]
            except Exception as e:
                logging.error("Error: {}".format(str(e)))

        return []
        

    def password(self, service, username):
        self.create(service, username, str(uuid.uuid4()))
