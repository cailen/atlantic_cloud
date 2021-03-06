atlantic_cloud
=========

The Ansible module for Atlantic.Net Cloud

0.2.0 - 07/07/17: 

Add new state 'restarted' to make the logic for restarting servers more straightforward.

Unique names: One can now query the API of an already existing server with 'servername'. This will return 
an error if there is more than one server that has this name (non-case-sensitive). If your servers all 
have the same name, then either change the server names in Cloud or use the instanceid method.

0.1.6 - 06/17/17: Fixed provisioning with backups. You must choose 'Y' or 'N'. Default is 'N'.

Requirements
------------
````
/library/atlantic_cloud.py - The Ansible module for Atlantic.Net Cloud
https://github.com/cailen/anetpy - The Atlantic.Net Cloud API Python wrapper
````

Dependencies
------------
````
anetpy
````

Options
-------
````
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
  enablebackup:
    description:
     - Optional, string, enables backups for your cloudserver.
    default: "no"
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
     - The type of restart you want to perform (hard or soft). (Note: 'hard' is the default.)
````

Example Playbook
----------------
````
- hosts: localhost
  vars:
    - public_key: XXX
    - private_key: XXX

  tasks:

    - name: Atlantic_Net Cloud - Create new server
      atlantic_cloud:
         public_key: "{{public_key}}"
         private_key: "{{private_key}}"
         state: present
         servername: test-server"
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
         servername: test-server
         public_key: "{{public_key}}"
         private_key: "{{private_key}}"

    - name: Server ID
      debug:
         msg: "ID is {{ my_cloudserver.results.instanceid }}"
    - name: Server IP
      debug:
         msg: "IP is {{ my_cloudserver.results.vm_ip_address }}"

    - name: Atlantic_Net Cloud - Reboot server
      atlantic_cloud:
         public_key: "{{public_key}}"
         private_key: "{{private_key}}"
         state: restarted
         instanceid: "{{my_cloudserver.results.instanceid}}"
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
         public_key: "{{public_key}}"
         private_key: "{{private_key}}"
         state: absent
         instanceid: "{{my_cloudserver.results.instanceid}}"
      register: result
    - name: Server deleted message
      debug:
         var: result
````
License
-------

BSD

Author Information
------------------

Derek Wiedenhoeft
- @cailenletigre
- http://derekdesignsorlando.com
- derek [at] derekdesignsorlando.com