# atlantic_cloud: The (unofficial) Atlantic.Net Cloud API for Ansible

Requirements:
/library/atlantic_cloud.py - The Ansible module for Atlantic.Net Cloud
https://github.com/cailen/anetpy - The Atlantic.Net Cloud API Python wrapper

Sample Ansible Scripts:

ghost.yml - Ghost Blogging Platform
Note: This also generates a file in the same directory that contains the login information for the server.

sample.yml - Creating Atlantic.Net Cloud Servers

=================

Module name: atlantic_cloud

Options:

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
  reboottype:
    description:
     - The type of restart you want to perform (hard or soft). (Note: 'hard' is recommended.)

EXAMPLES

---
- hosts: localhost
  vars:
    - cu_id: XXX
    - public_key: XXX
    - private_key: XXX

  tasks:

    - name: Atlantic_Net Cloud - Create new server
      atlantic_cloud:
         state: present
         servername: "{{cu_id}}-test-server"
         vm_location: USEAST1
         imageid: CentOS-7.2_64bit
         planname: "G2.4GB"
         ssh_key: "ansible"
      register: my_cloudserver

    - name: Wait for the server to come online...
      local_action:
        module: wait_for
          host={{ my_cloudserver.results.ip_address }}
          port=22
          delay=1
          timeout=300

    - name: Atlantic_Net Cloud - Get server details from the server just created
      atlantic_cloud:
         state: present
         instanceid: "{{my_cloudserver.results.instanceid}}"

    - name: Server ID
      debug:
         msg: "ID is {{ my_cloudserver.results.instanceid }}"
    - name: Server IP
      debug:
         msg: "IP is {{ my_cloudserver.results.vm_ip_address }}"

    - name: Atlantic_Net Cloud - Reboot server
      atlantic_cloud:
         state: present
         instanceid: "{{my_cloudserver.results.instanceid}}"
         reboottype: "hard"
      register: result
    - name: Server reboot message
      debug:
         var: result

    - name: Wait for the server to come online...
      local_action:
        module: wait_for
          host={{ my_cloudserver.results.ip_address }}
          port=22
          delay=1
          timeout=300

    - name: Atlantic_Net Cloud - Delete the server
      atlantic_cloud:
         state: absent
         instanceid: "{{my_cloudserver.results.instanceid}}"
      register: result
    - name: Server deleted message
      debug:
         var: result

