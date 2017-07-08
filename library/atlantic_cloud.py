#!/usr/bin/python
# -*- coding: utf-8 -*-

# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'version': '0.2.0'}

DOCUMENTATION = '''
---
module: atlantic_cloud
short_description: Create/delete a cloudserver/SSH_key in Atlantic.Net
description:
     - Create/delete a cloudserver in Atlantic.Net and optionally wait for it to be 'running', or deploy an SSH key.
author: "Derek Wiedenhoeft (@cailenletigre)"
options:
  state:
    description:
     - Indicate desired state of the target.
    default: present
    choices: ['present', 'active', 'absent', 'deleted', 'restarted']
  public_key:
    description:
     - Atlantic.Net public API key.
  private_key:
     - Atlantic.Net private API key.
  instanceid:
    description:
     - Numeric, the cloudserver id you want to operate on.
  servername:
    description:
     - String, this is the name of the cloudserver - must be formatted by hostname rules, or the name of a SSH key.
  planname:
    description:
     - This is the slug of the size you would like the cloudserver created with.
  imageid:
    description:
     - This is the slug of the image you would like the cloudserver created with.
  vm_location:
    description:
     - This is the slug of the region you would like your server to be created in.
    default: 'USEAST1'
    choices: ['USEAST1', 'USEAST2', 'USCENTRAL1', 'USWEST1', 'CAEAST1', 'EUWEST1']
  enablebackup:
    description:
     - Optional, enables backups for your cloudserver.
    default: "N"
    choices: [ "Y", "N" ]
  wait:
    description:
     - Wait for the cloudserver to be in state 'running' before returning.  If wait is "no" an ip_address may not be returned.
    default: "yes"
    choices: [ "yes", "no" ]
  wait_timeout:
    description:     
    - How long before wait gives up, in seconds.
    default: 300
  ssh_key:
    description:
     - The name of the public SSH key you want to add to your account.
  reboottype:
    description:
     - The type of reboot: soft or hard. (Suggestion is to hard reboot)
    default: "hard"
    choices: [ "hard", "soft"]

EXAMPLES

# Create a new cloudserver
# Will return the cloudserver details including the cloudserver id (used for idempotence)
- atlantic_cloud:
    state: present
    servername: mycloudserver
    public_key: XXX
    private_key: XXX
    planname: G2.2GB
    vm_location: USEAST2
    imageid: ubuntu-14.04_64bit
    wait_timeout: 500
  register: my_cloudserver

- name: Server ID
  debug:
    msg: "ID is {{ my_cloudserver.results.instanceid }}"
- name: Server IP
  debug:
    msg: "IP is {{ my_cloudserver.results.vm_ip_address }}"

# Ensure a cloudserver is present
# If cloudserver id already exist, will return the cloudserver details and changed = False
- atlantic_cloud:
    state: present
    instanceid: 123456
    public_key: XXX
    private_key: XXX
    wait_timeout: 500
    
# Create a cloudserver with ssh key
# The ssh key id can be passed as argument at the creation of a cloudserver (see ssh_key).
# The key is used to connect as root to the cloudserver.
- atlantic_cloud:
    state: present
    ssh_key: XXX
    servername: mycloudserver
    public_key: XXX
    private_key: XXX
    planname: G2-2GB
    vm_location: USEAST2
    imageid: ubuntu-14.04_64bit

'''
###
# This file inspired by digital_ocean.py, found on Github at
# https://github.com/ansible/ansible-modules-core/blob/devel/cloud/digital_ocean/digital_ocean.py
###

import os
import time
import traceback
import logging
from distutils.version import LooseVersion

HAS_ANETPY = False
try:
    import anetpy
    from anetpy.manager import AnetError, AnetManager
    if LooseVersion(anetpy.__version__) >= LooseVersion('0.0.1'):
        HAS_ANETPY = True
except ImportError:
    pass

from ansible.module_utils.basic import AnsibleModule


class TimeoutError(Exception):
    def __init__(self, msg, id_):
        super(TimeoutError, self).__init__(msg)
        self.instanceid = id_


class JsonfyMixIn(object):
    def to_json(self):
        return self.__dict__


class Cloudserver(JsonfyMixIn):
    """ Provides the means and methods to retrieve and manage Atlantic.Net Cloudservers."""
    manager = None

    def __init__(self, cloudserver_json_resp):
        if 'vm_status' in cloudserver_json_resp:
            self.vm_status = cloudserver_json_resp['vm_status']
        else:
            self.vm_status = 'NEW'
        self.__dict__.update(cloudserver_json_resp)

    def is_powered_on(self):
        """ Check if a Cloudserver's status is RUNNING. """

        return self.vm_status == 'RUNNING'

    def update_attr(self, attrs=None):
        """ Update the dictionary of a Cloudserver."""

        if attrs:
            for k, v in attrs.iteritems():
                for x, y in v.iteritems():
                    setattr(self, x.lower(), y)
        else:
            json = self.manager.show_cloudserver(self.instanceid)
            if json['item']['vm_status']:
                self.update_attr(json)

    def power_on(self):
        """ Power on a server if the status is STOPPED. """

        assert self.vm_status == 'STOPPED'  # Can only power on a stopped one.
        json = self.manager.power_cycle_cloudserver(self.instanceid, reboottype='hard')
        self.update_attr(json)

    def ensure_powered_on(self, wait=True, wait_timeout=300):
        """ Check to make sure the server is powered on. """

        if self.is_powered_on():
            return True
        if self.vm_status == 'STOPPED':  # powered off
            self.power_on()
        if wait:
            end_time = time.time() + wait_timeout
            while time.time() < end_time:
                time.sleep(min(20, end_time - time.time()))
                self.update_attr()
                if self.is_powered_on():
                    if not self.vm_ip_address:
                        raise TimeoutError('No IP address was found.', self.instanceid)
                    return True
            raise TimeoutError('Wait for cloudserver running timeout', self.instanceid)
        return False

    def reboot(self, instanceid, reboottype):
        """ Reboot the server. """

        return self.manager.power_cycle_cloudserver(instanceid, reboottype)

    def destroy(self, instanceid):
        """ Delete the server. """

        return self.manager.destroy_cloudserver(instanceid)

    @classmethod
    def setup(cls, public_key, private_key):
        """ Setup an instance of the AnetManager class inside of the Cloudserver class for
        API calls. """

        cls.manager = AnetManager(public_key, private_key)

    @classmethod
    def add(cls, servername, planname, imageid, vm_location, key_id=None, enablebackup='N'):
        """ Create a new Cloudserver. """
        
        cloudserver = cls.manager.new_cloudserver(servername, planname, imageid, vm_location, key_id=key_id, enablebackup=enablebackup)
        for k, v in cloudserver.items():
            return cls(dict((x.lower(), y) for x, y in v.iteritems()))

    @classmethod
    def find(cls, instanceid=None, servername=None):
        """ After retrieving a list of all Cloudservers, return a *unique* Cloudserver.
        If there is not a Cloudserver that matches either the instanceid or servername,
        or there is more than one Cloudserver that matches the servername, return FALSE."""

        cloudservers = cls.list_all()
        if instanceid:
            for cloudserver in cloudservers:
                if cloudserver.instanceid == str(instanceid):
                    return cloudserver
        if servername:
            s = set()
            for cloudserver in cloudservers:
                if str(cloudserver.vm_description).lower() == str(servername).lower():
                    if (cloudserver.vm_description).lower() in s: return False
                    s.add(cloudserver.vm_description)
                    return cloudserver
        return False

    @classmethod
    def list_all(cls):
        """ Retrieves a list of all active Cloudservers. """

        cloudservers = {}
        cloud_list = []
        cloudservers = cls.manager.all_active_cloudservers()
        for k, v in cloudservers.items():
            cloud_list.append((dict((x.lower(), y) for x, y in v.iteritems())))
        return map(cls, cloud_list)

    @classmethod
    def describe_server(cls, instanceid):
        """ Returns the detailed information available from the API for a Cloudserver. """

        return cls.manager.show_cloudserver(instanceid)

class SSH(JsonfyMixIn):
    """ Provides the means and methods to retrieve and manage SSH keys added to Atlantic.Net."""
    manager = None

    def __init__(self, key_id_json_resp):
        self.__dict__.update(key_id_json_resp)
    update_attr = __init__

    @classmethod
    def setup(cls, public_key, private_key):
        """ Setup an instance of the AnetManager class inside of the SSH class for
        API calls. """

        cls.manager = AnetManager(public_key, private_key)

    @classmethod
    def find(cls, key_name):
        """ After retrieving a list of all SSH keys, return a *unique* SSH key. If there is not
        an SSH key that matches the key_name, return FALSE."""

        if not key_name:
            return False
        keys = cls.list_all()
        for key in keys:
            if key.key_name == key_name:
                return key.key_id
        return False

    @classmethod
    def list_all(cls):
        """ Retrieves a list of all SSH keys. """

        ssh_keys = {}
        ssh_keys_list = []
        ssh_keys = cls.manager.all_ssh_keys()
        for k, v in ssh_keys.items():
            ssh_keys_list.append((dict((x.lower(), y) for x, y in v.iteritems())))
        return map(cls, ssh_keys_list)

def core(module):
    def getkeyordie(k):
        """ For keys that are required to move on, check if the key exists. If it exists,
        then pass the key back. If it does not exist, tell Ansible to exit."""

        v = module.params[k]
        if v is None:
            module.fail_json(msg='Unable to load %s' % k)
        return v
    try:
        public_key = module.params['public_key']
        private_key = module.params['private_key']
    except KeyError as e:
        module.fail_json(msg='Unable to load %s' % e.message)

    changed = True
    state = module.params['state']
    msg = ""

    # Setup adds the AnetManager class to Cloudserver so API calls can be made
    Cloudserver.setup(public_key, private_key)

    # Check what state is being checked for.
    # Active and Present will either give details about a unique server (based 
    # on instanceid or servername), make sure a Cloudserver that is STOPPED
    # is turned started again, or create a new Cloudserver.
    #
    # Restarted will restart a unique server (based on instanceid or servername).
    #
    # Absent and Deleted will either make sure a unique server is already removed or
    # will delete the server if it is present currently.
    if state in ('active', 'present'):
        if module.params['instanceid']:
            # Return a Cloudserver's details if there is an instanceid that matches
            cloudserver = Cloudserver.find(instanceid=module.params['instanceid'])
            if cloudserver:
                results = Cloudserver.describe_server(instanceid=cloudserver.instanceid)['item']
                changed = False
                msg = "Server details"
        # Return a Cloudserver's details if there is one and only one servername that matches
        # (if it's not unique, it returns false)
        elif module.params['servername']:
            cloudserver = Cloudserver.find(servername=module.params['servername'])
            if cloudserver:
                results = Cloudserver.describe_server(instanceid=cloudserver.instanceid)['item']
                changed = False
                msg = "Server details"
            # Create a new server if you've made it this far
            elif module.params['servername'] and not module.params['instanceid']:
                if module.params['ssh_key']:
                    SSH.setup(public_key, private_key)
                    ssh_key = SSH.find(module.params['ssh_key'])
                cloudserver = Cloudserver.add(
                    servername=getkeyordie('servername'),
                    planname=getkeyordie('planname'),
                    imageid=getkeyordie('imageid'),
                    vm_location=getkeyordie('vm_location'),
                    key_id=ssh_key,
                    enablebackup=module.params['enablebackup'],
                    )
                results = cloudserver.to_json()
                msg = "New server credentials"
                changed = True
        if cloudserver:
            # Make sure the server is "RUNNING"
            cloudserver.ensure_powered_on()
            module.exit_json(changed=changed, msg=msg, results=results)
        module.fail_json(changed=False, msg="No server found")
    elif state in 'restarted':
        if module.params['instanceid']:
            # Return a server is there is an instanceid that matches
            cloudserver = Cloudserver.find(instanceid=module.params['instanceid'])
            if not cloudserver:
                msg = "A server with this ID does not exist."
        elif module.params['servername']:
            # Return a Cloudserver if there is one and only one servername that matches
            # (if it's not unique, it returns false)
            cloudserver = Cloudserver.find(servername=module.params['servername'])
            if not cloudserver:
                msg = "A server with this name either does not exist or there is more than one server with this name."
        if cloudserver:
            # Reboot the server
            results = cloudserver.reboot(instanceid=cloudserver.instanceid, reboottype=module.params['reboottype'])
            # Make sure the server is "RUNNING"
            cloudserver.ensure_powered_on()
            msg = "Server has been rebooted"
            module.exit_json(changed=True, msg=msg, results=results)
        else:
            # If no Cloudserver was returned, tell Ansible
            module.fail_json(changed=False, msg=msg)
    elif state in ('absent', 'deleted'):
        if module.params['instanceid']:
            # Return a server is there is an instanceid that matches
            cloudserver = Cloudserver.find(instanceid=module.params['instanceid'])
            if not cloudserver:
                msg = "A server with this ID does not exist."
        elif module.params['servername']:
            # Return a Cloudserver if there is one and only one servername that matches
            # (if it's not unique, it returns false)
            cloudserver = Cloudserver.find(servername=module.params['servername'])
            if not cloudserver:
                msg = "A server with this name either does not exist or there is more than one server with this name."
        if cloudserver:
            # Delete the Cloudserver
            destroy_results = cloudserver.destroy(cloudserver.instanceid)
            module.exit_json(changed=True, msg="The server has been removed.", results=destroy_results)
        module.exit_json(changed=False, msg=msg)

def main():
    module = AnsibleModule(
        argument_spec = dict(
            state = dict(choices=['active', 'present', 'absent', 'deleted', 'restarted'], default='present'),
            public_key = dict(required=True, type='str'),
            private_key = dict(required=True, type='str'),
            servername = dict(type='str'),
            planname = dict(type='str'),
            imageid = dict(type='str'),
            vm_location = dict(type='str', choices=['USEAST1', 'USEAST2', 'USCENTRAL1', 'USWEST1', 'CAEAST1', 'EUWEST1']),
            enablebackup = dict(type='str', choices=['Y', 'N'], default='N'),
            instanceid = dict(type='int'),
            wait = dict(type='bool', default=True),
            wait_timeout = dict(default=300, type='int'),
            ssh_key = dict(type='str'),
            server_qty = dict(type='int', default=1),
            reboottype = dict(type='str', choices=['hard', 'soft'], default='hard')
        ),
        required_together = [
            ['planname', 'imageid', 'vm_location'],
        ],
        required_one_of = [
            ['instanceid', 'servername']
        ],
    )

    if not HAS_ANETPY:
        module.fail_json(msg='anetpy >= 0.1.0 required for this module')

    try:
        core(module)
    except TimeoutError as e:
        module.fail_json(msg=str(e), id=e.id)
    except (AnetError, Exception) as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())

if __name__ == '__main__':
    main()
