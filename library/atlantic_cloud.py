import ansible.module_utils.basic
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
                    'version': '0.1.5'}

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
    choices: ['present', 'active', 'absent', 'deleted']
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
  enablebackup:
    description:
     - Optional, Boolean, enables backups for your cloudserver.
    version_added: "1.6"
    default: "no"
    choices: [ "yes", "no" ]
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

notes:
  - none  
requirements:
  - "python >= 2.6"
  - anetpy
'''


EXAMPLES = '''
# Ensure a SSH key is present
# If a key matches this name, will return the ssh key id and changed = False
# If no existing key matches this name, a new key is created, the ssh key id is returned and changed = False

- atlantic_cloud:
    state: present
    command: ssh
    name: my_ssh_key
    key_id: 'ssh-rsa AAAA...'
    public_key: XXX
    private_key: XXX

# Create a new cloudserver
# Will return the cloudserver details including the cloudserver id (used for idempotence)

- atlantic_cloud:
    state: present
    command: cloudserver
    name: mycloudserver
    public_key: XXX
    private_key: XXX
    planname: G2.2GB
    vm_location: USEAST2
    imageid: ubuntu-14.04_64bit
    wait_timeout: 500
  register: my_cloudserver

- debug:
    msg: "ID is {{ my_cloudserver.cloudserver.id }}"

- debug:
    msg: "IP is {{ my_cloudserver.cloudserver.ip_address }}"

# Ensure a cloudserver is present
# If cloudserver id already exist, will return the cloudserver details and changed = False
# If no cloudserver matches the id, a new cloudserver will be created and the cloudserver details (including the new id) are returned, changed = True.

- atlantic_cloud:
    state: present
    command: cloudserver
    instanceid: 123
    servername: mycloudserver
    public_key: XXX
    private_key: XXX
    planname: G2.2GB
    vm_location: USEAST2
    imageid: ubuntu-14.04_64bit
    wait_timeout: 500

# Create a cloudserver with ssh key
# The ssh key id can be passed as argument at the creation of a cloudserver (see ssh_key_ids).
# Several keys can be added to ssh_key_ids as id1,id2,id3
# The keys are used to connect as root to the cloudserver.

- atlantic_cloud:
    state: present
    key_id: XXX
    servername: mycloudserver
    public_key: XXX
    private_key: XXX
    planname: G2-2GB
    vm_location: USEAST2
    imageid: ubuntu-14.04_64bit

'''

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
    manager = None

    def __init__(self, cloudserver_json_resp):
        if 'vm_status' in cloudserver_json_resp:
            self.vm_status = cloudserver_json_resp['vm_status']
        else:
            self.vm_status = 'NEW'
        self.__dict__.update(cloudserver_json_resp)

    def is_powered_on(self):
        return self.vm_status == 'RUNNING'

    def update_attr(self, attrs=None):
        if attrs:
            for k, v in attrs.iteritems():
                for x, y in v.iteritems():
                    setattr(self, x.lower(), y)
        else:
            json = self.manager.show_cloudserver(self.instanceid)
            if json['item']['vm_status']:
                self.update_attr(json)

    def power_on(self):
        assert self.vm_status == 'STOPPED'  # Can only power on a stopped one.
        json = self.manager.power_cycle_cloudserver(self.instanceid, reboottype='hard')
        self.update_attr(json)

    def ensure_powered_on(self, wait=True, wait_timeout=300):
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
        return self.manager.power_cycle_cloudserver(instanceid, reboottype)

    def destroy(self, instanceid):
        return self.manager.destroy_cloudserver(instanceid)

    @classmethod
    def setup(cls, public_key, private_key):
        cls.manager = AnetManager(public_key, private_key)

    @classmethod
    def add(cls, servername, planname, imageid, vm_location, key_id=None, enablebackup=False):
        if(enablebackup){
            enablebackup = 'Y'
        }
        else{
            enablebackup = 'N'
        }
        cloudserver = cls.manager.new_cloudserver(servername, planname, imageid, vm_location, key_id=key_id, enablebackup=enablebackup_lower)
        for k, v in cloudserver.items():
            return cls(dict((x.lower(), y) for x, y in v.iteritems()))

    @classmethod
    def find(cls, instanceid):
        cloudservers = cls.list_all()
        for cloudserver in cloudservers:
            if cloudserver.instanceid == str(instanceid):
               return cloudserver
        return False

    @classmethod
    def list_all(cls):
        cloudservers = {}
        cloud_list = []
        cloudservers = cls.manager.all_active_cloudservers()
        for k, v in cloudservers.items():
            cloud_list.append((dict((x.lower(), y) for x, y in v.iteritems())))
        return map(cls, cloud_list)

class SSH(JsonfyMixIn):
    manager = None

    def __init__(self, key_id_json_resp):
        self.__dict__.update(key_id_json_resp)
    update_attr = __init__

    @classmethod
    def setup(cls, public_key, private_key):
        cls.manager = AnetManager(public_key, private_key)

    @classmethod
    def find(cls, key_name):
        if not key_name:
            return False
        keys = cls.list_all()
        for key in keys:
            if key.key_name == key_name:
                return key.key_id
        return False

    @classmethod
    def list_all(cls):
        ssh_keys = {}
        ssh_keys_list = []
        ssh_keys = cls.manager.all_ssh_keys()
        for k, v in ssh_keys.items():
            ssh_keys_list.append((dict((x.lower(), y) for x, y in v.iteritems())))
        return map(cls, ssh_keys_list)

def core(module):
    def getkeyordie(k):
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
    ssh_key = module.params['ssh_key']

    Cloudserver.setup(public_key, private_key)
    if state in ('active', 'present'):
        if module.params['instanceid']:
            # Return a server is there is an instanceid that matches
            cloudserver = Cloudserver.find(instanceid=module.params['instanceid'])
            if cloudserver:
                # Reboot selected server
                if module.params['reboottype']:
                    results = cloudserver.reboot(instanceid=module.params['instanceid'], reboottype=module.params['reboottype'])
                    msg = "Server has been rebooted"
                    changed =  True
                else:
                    changed = False
                    msg = "Server details"

        # Create a new server if you've made it this far
        if module.params['servername'] and not module.params['instanceid']:
            if module.params['ssh_key']:
                SSH.setup(public_key, private_key)
                ssh_key = SSH.find(ssh_key)
            cloudserver = Cloudserver.add(
                servername=getkeyordie('servername'),
                planname=getkeyordie('planname'),
                imageid=getkeyordie('imageid'),
                vm_location=getkeyordie('vm_location'),
                key_id=ssh_key,
                enablebackup=module.params['enablebackup'],
                )
            msg = "New server credentials"
            changed = True

        if cloudserver:
            # Make sure the server is "RUNNING"
            cloudserver.ensure_powered_on()
            changed = True
            results = cloudserver.to_json()
            # Print out the results
            module.exit_json(changed=changed, msg=msg, results=results)
        module.fail_json(changed=False, msg="No server found")

    # Delete a server or check to see if it doesn't exist
    elif state in ('absent', 'deleted'):
        if module.params['instanceid']:
            # Return a server is there is an instanceid that matches
            cloudserver = Cloudserver.find(instanceid=module.params['instanceid'])
            # First, try to find a cloudserver by instanceid.
            if cloudserver:
                destroy_results = cloudserver.destroy(module.params['instanceid'])
                module.exit_json(changed=True, msg="The server has been removed.", results=destroy_results)
        module.fail_json(changed=False, msg='No ID specified or invalid ID specified.')

def main():
    module = AnsibleModule(
        argument_spec = dict(
            state = dict(choices=['active', 'present', 'absent', 'deleted'], default='present'),
            public_key = dict(type='str', default='ATL8f59337f60fb45e4ff600c38e62ab540'),
            private_key = dict(type='str', default='66f002a2b6c5d742a9ce6d6e4de333534c73b128'),
            servername = dict(type='str'),
            planname = dict(type='str'),
            imageid = dict(type='str'),
            vm_location = dict(type='str'),
            enablebackup = dict(type='bool', default='no'),
            instanceid = dict(type='int'),
            wait = dict(type='bool', default=True),
            wait_timeout = dict(default=300, type='int'),
            ssh_key = dict(type='str'),
            server_qty = dict(type='int', default=1),
            reboottype = dict(type='str',)
        ),
        required_together = [
            ['planname', 'imageid', 'vm_location', 'servername'],
        ],
        required_one_of = [
            ['instanceid','servername']
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
