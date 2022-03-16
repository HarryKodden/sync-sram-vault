# app.py

import os
import logging
import json
import uuid

import ldap3 as ldap

class LDAP(object):
    
    def __init__(self):

        try:
            s = ldap.Server(os.environ['LDAP_HOST'], get_info=ldap.ALL, mode=os.environ.get("LDAP_MODE", ldap.IP_V6_PREFERRED))

            self.session = ldap.Connection(s, user=os.environ['LDAP_BIND_DN'], password=os.environ['LDAP_PASSWORD'])
            if not self.session.bind():
               raise("Exception during bind: {}".format(c.result))

            logging.debug("LDAP Connected !")

        except Exception as e:
            logging.error("Problem connecting to LDAP {} error: {}".format(os.environ['LDAP_HOST'], str(e)))

        self.people = {}
        self.groups = {}

    def __enter__(self, people_args={}, group_args={}):
        self.get_people(**people_args)
        self.get_groups(**group_args)

        return self

    def __exit__(self, exception_type, exception_value, traceback):
        self.session.unbind()

    def __repr__(self):
        return json.dumps(self.json(), indent=4, sort_keys=True)

    def json(self):
        return {
            'people': self.people,
            'groups': self.groups
        }

    def search(self, base, searchScope=ldap.SUBTREE,
            searchFilter="(objectclass=*)",
            retrieveAttributes=[]):

        logging.debug("[LDAP SEARCH], BASE: {}, FILTER: {}".format(base, searchFilter))

        result = {}
        try:
            self.session.search(
                base, searchFilter,
                searchScope,
                attributes=retrieveAttributes
            )

            for entry in self.session.response:
                result[entry['dn']] = self.attributes(entry['raw_attributes'])

        except Exception as e:
            result = None
            logging.error("[LDAP] SEARCH: '%s' ERROR: %s\n" % (base, str(e)))

        return result

    @staticmethod
    def attributes(x):
        attributes = {}

        for a in x.keys():
            attributes[a] = []
            for v in x[a]:
                attributes[a].append(v.decode())

        return attributes

    def get_people(self, base=os.environ.get('LDAP_BASE_DN',''), searchFilter="(objectClass=inetOrgPerson)"):

        ldap_user_key = os.environ.get('LDAP_USER_KEY', 'uid')

        for dn, attributes in self.search(
                base,
                searchFilter="(&{}({}=*))".format(searchFilter, ldap_user_key),
                retrieveAttributes=['*']).items():

            logging.debug("[LDAP PERSON]: {}...".format(dn))

            if ldap_user_key not in attributes:
                logging.error("Missing '{}' attribute in LDAP USER Object !".format(ldap_user_key))
                continue

            if len(attributes[ldap_user_key]) > 1:
                logging.error("LDAP User key '{}' must be 1 value !".format(ldap_user_key))
                continue

            key = attributes[ldap_user_key][0]

            self.people[key] = {
                'attributes': attributes
            }

    def get_groups(self, base=os.environ.get('LDAP_BASE_DN',''), searchFilter="(objectClass=groupOfMembers)"):
        ldap_group_key = os.environ.get('LDAP_GROUP_KEY', 'cn')

        for dn, attributes in self.search(
                base, 
                searchFilter="(&{}({}=*))".format(searchFilter, ldap_group_key),
                retrieveAttributes=['*']).items():

            logging.debug("[LDAP GROUP]: {}...".format(dn))

            if ldap_group_key not in attributes:
                logging.error("Missing '{}' attribute in LDAP GROUP Object !".format(ldap_group_key))
                continue

            if len(attributes[ldap_group_key]) > 1:
                logging.error("LDAP Group key '{}' must be 1 value !".format(ldap_group_key))
                continue

            key = attributes[ldap_group_key][0]

            members = []

            if 'member' in attributes:

                for member in attributes['member']:

                    m = member.split(',')[0].split('=')[1]

                    if m not in self.people:
                        logging.error("Member {} not in LDAP People !".format(m))
                        continue

                    members.append(m)

            attributes['member'] = members

            self.groups[key] = {
                'attributes': attributes
            }
