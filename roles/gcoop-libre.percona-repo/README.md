Percona Repo
============

This role adds the Percona APT repositories to Debian/Ubuntu systems.

Requirements
------------

None.

Role Variables
--------------

Available variables are listed below, along with default values (see `defaults/main.yml`):

    percona_repo_download_local: False

When this option is set to `True`, the `Percona deb file` will be downloaded locally and then it will be uploaded to the remote host for it's installation.

    percona_repo_temp_directory_mask: /tmp/percona_repo.XXXXXXXXXX

This property sets the mask used to create the local temporal directory where the `Percona deb file` will be locally downloaded.

Dependencies
------------

None.

Example Playbook
----------------

    - hosts: dbservers
      roles:
         - gcoop-libre.percona-repo

License
-------

GPLv2

Author Information
------------------

This role was created in 2016 by [gcoop Cooperativa de Software Libre](http://gcoop.coop).
