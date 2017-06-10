
install_snorby() {

echo
echo '---------------------------------------------'
echo "Getting ready to install Snorby"
echo '---------------------------------------------'
sleep 3

cd /opt
unzip /opt/snorby-master.zip
mv /opt/snorby-master /opt/snorby
sed -i 's/0.9.2/\> 0.9.2/' /opt/snorby/Gemfile
sed -i "s/1.5.0'/1.5.0' \ngem 'orm_adapter'/" /opt/snorby/Gemfile
sed -i 's/(0.9.2)/(0.9.2.2)/' /opt/snorby/Gemfile.lock
cp /opt/snorby/config/snorby_config.yml.example /opt/snorby/config/snorby_config.yml
cp /opt/snorby/config/database.yml.example /opt/snorby/config/database.yml
sed -i 's/root/snorby/g' /opt/snorby/config/database.yml
sed -i 's/"Enter Password Here"/snorby/' /opt/snorby/config/database.yml
sed -i 's/time_zone = CONFIG\[:time_zone\]/time_zone = "America\/New_York"/' /opt/snorby/config/application.rb
sed -i '20,25s/#//'  /opt/snorby/config/initializers/mail_config.rb
# Email Reports Fix - Added v4.3
sed -i 's/def daily_report(email, timezone="UTC")/def daily_report(email="device-alerts@atlantic.net", timezone="America\/\New_York")/' /opt/snorby/app/mailers/report_mailer.rb
sed -i 's/def weekly_report(email, timezone="UTC")/def weekly_report(email="device-alerts@atlantic.net", timezone="America\/\New_York")/' /opt/snorby/app/mailers/report_mailer.rb
sed -i 's/def monthly_report(email, timezone="UTC")/def monthly_report(email="device-alerts@atlantic.net", timezone="America\/\New_York")/' /opt/snorby/app/mailers/report_mailer.rb
# Fix wkhtmltopdf path in main config. - Added v4.3.1
sed -i 's#wkhtmltopdf: /Users/mephux/.rvm/gems/ruby-1.9.2-p0/bin/wkhtmltopdf#wkhtmltopdf: /usr/local/bin/wkhtmltopdf#' /opt/snorby/config/snorby_config.yml

cd snorby && bundle install
rake snorby:setup

mysql -r -p${pfpass} -e 'update snorby.users set encrypted_password="$2a$10$SIJfp4wCy9J2qjaUSOosaOPm57uaDzMkVwseZuZab0JTN9eMWULla", email="device-alerts@atlantic.net", timezone="Eastern Time (US & Canada)", email_reports="1" where email ="snorby@snorby.org";'

# Create Init script
cat << \EOF > /etc/init.d/snorby

#!/bin/sh
#
# snorby         Start/Stop the snorby daemon.
# April 13, 2010 -- andres.hans  <andre...@gmail.com>
#  -initial version
#
# chkconfig: 2345 90 60
# description: Snorby, snort frontend

### BEGIN INIT INFO
# Provides: snorby
# Required-Start: $local_fs $mysqld
# Required-Stop:
# Default-Start:  2345
# Default-Stop: 90
# Short-Description: run snorby daemon
# Description: Snorby, snort frontend
### END INIT INFO

RETVAL=0
prog="snorby"
exec="/usr/bin/ruby"
params="rails server -e production -d"
lockfile=/var/lock/subsys/snorby
#change this to your snorby instalation
directory="/opt/snorby/"
config=$directory/config/database.yml
pid=$directory/tmp/pids/server.pid

# Source function library.
. /etc/rc.d/init.d/functions

[ -e /etc/sysconfig/$prog ] && . /etc/sysconfig/$prog

start() {
    [ -x $exec ] || exit 5
    [ -f $config ] || exit 6
    echo -n $"Starting $prog: "
    cd $directory
    rails r "Snorby::Worker.start"
    daemon $params && success || failure
    retval=$?
    echo
    [ $retval -eq 0 ] && touch $lockfile
    return $retval
}

stop() {
    echo -n $"Stopping $prog: "
        if [ -n "`cat $pid`" ]; then
                killproc $exec
                RETVAL=3
        else
                failure $"Stopping $prog"
        fi
    retval=$?
    echo
    [ $retval -eq 0 ] && rm -f $lockfile && rm -f $pid
    return $retval
}

restart() {
    stop
    start
}

reload() {
        echo "Not Implemented"
        retval=$?
        echo
}

force_reload() {
        # new configuration takes effect after restart
    restart
}

rh_status() {
    # run checks to determine if the service is running or use generic
status
    status -p $pid $prog
}

rh_status_q() {
    rh_status >/dev/null 2>&1
}


case "$1" in
    start)
        rh_status_q && exit 0
        $1
        ;;
    stop)
        rh_status_q || exit 0
        $1
        ;;
    restart)
        $1
        ;;
    reload)
        rh_status_q || exit 7
        $1
        ;;
    force-reload)
        force_reload
        ;;
    status)
        rh_status
        ;;
    condrestart|try-restart)
        rh_status_q || exit 0
        restart
        ;;
    *)
        echo $"Usage: $0 {start|stop|status|restart|condrestart|try-
restart|reload|force-reload}"
        exit 2
esac
exit $?

EOF

chmod 755 /etc/init.d/snorby
chkconfig snorby on

echo '30 * * * * /opt/monitor_snorby.sh' >> /etc/crontab

cat << \EOF > /opt/monitor_snorby.sh

#!/bin/sh

stat=$(service snorby status | grep -o 'running')
to='device-alerts@atlantic.net'
name=`hostname`
from="${name}@snorby.org"

if [[ -z $stat ]]; then
 echo "The the SNORBY service has stopped on ${name}" | mail -r ${from} -s "Warning from ServerID: `hostname`" $to
fi

EOF

chmod 755 /opt/monitor_snorby.sh

stat=$?
if [[ $stat -ne '0' ]] ; then
 echo "Error detected: Exiting"
 exit 1
fi

}

install_iptables() {

echo
echo '---------------------------------------------'
echo "Getting ready to install IPtables"
echo '---------------------------------------------'
sleep 3

cat << EOF > /etc/sysconfig/iptables

*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:ATLANTIC-NET-MGMT - [0:0]
:PUBLIC - [0:0]
:TRUSTED - [0:0]

# Filter all INPUT traffic through custom chains:
-A INPUT -j ATLANTIC-NET-MGMT
-A INPUT -j PUBLIC

# Allow traffic from loopback interface:
-A INPUT -i lo -j ACCEPT

# Allow traffic from trusted interfaces
-A INPUT -s 172.16.254.220 -m comment --comment "Hera Backups" -j ACCEPT

# Allow already established traffic
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

####################
# Custom Rule Chains
####################
# Allow traffic from Atlantic.Net Management Ranges:
-A ATLANTIC-NET-MGMT -s 209.208.0.192/26 -j ACCEPT
-A ATLANTIC-NET-MGMT -s ${pfip} -j ACCEPT
-A ATLANTIC-NET-MGMT -s 209.208.50.9 -j ACCEPT
-A ATLANTIC-NET-MGMT -s 209.208.50.11 -p udp -m udp --dport 161 -j ACCEPT

COMMIT

EOF

echo "IPtables Rules Set"
echo "Temporarily turning off IPtables...once you power off and power back on IPtables will turn back on"
service iptables stop

}

output_info() {

cat << EOF

=================
Mysql Information
=================
mysql root@localhost password: ${pfpass}
mysql root@127.0.0.1 password: ${pfpass}
mysql snort@${pfip} password: ${pfpass}
mysql snorby@localhost password: snorby

This script will auto start the Snorby Daemon
To start the Snorby Daemon run the following:

service snorby start
-or-
cd /opt/snorby ; rails server -e production -d

======================
Snort/Barnyard2 Config
======================
Insert the following into your Snort/Barnyard2 Config

- NOTE -
 Snorby will NOT send email reports still
 SNORT has sucessfully establish mysql
 connectivity to the SNORBY database.

Copy/Paste the following output WITHOUT THE '***'
*** output database: alert, mysql, dbname=snorby user=snort host=${pfip} password=${pfpass} ***

=================
WebUI Information
=================
http://<serverip>:3000
u: device-alerts@atlantic.net
p: Nrprocks!

EOF

}

# Check if we have our files
if [ -e "/opt/yaml-0.1.4.tar.gz" ] && \
   [ -e '/opt/wkhtmltox-linux-amd64_0.12.0-03c001d.tar.xz' ] && \
   [ -e '/opt/ruby-1.9.3p484-1.el6.x86_64.rpm' ] && \
   [ -e '/opt/ImageMagick-6.8.5-9.tar.gz' ] && \
   [ -e '/opt/snorby-master.zip' ]; then

install_base_deps
install_libyaml
install_wkhtmltopdf
install_Ruby
install_rails
install_ImageMagick
install_mysql
install_snorby
install_iptables
output_info

# Start Snorby daemon
echo "Starting Snorby..."
service snorby start
echo '================================================='
netstat -tulnp | grep 3000
echo '================================================='

else

echo '
Please make sure the following are present:
/opt/yaml-0.1.4.tar.gz
/opt/wkhtmltox-linux-amd64_0.12.0-03c001d.tar.xz
/opt/ruby-1.9.3p484-1.el6.x86_64.rpm
/opt/ImageMagick-6.8.5-9.tar.gz
/opt/snorby-master.zip
'

fi

