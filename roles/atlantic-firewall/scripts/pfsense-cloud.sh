#!/bin/sh

## Check which version of pfsense we're on ##
version=$(cat /etc/version | awk -F\- '{print $1}' | awk -F\. '{print $1"."$2}')

if [ $version == '2.3' ]; then

echo 'y' | /usr/sbin/pkg install python27
echo 'y' | /usr/sbin/pkg install xmlstarlet
echo 'y' | /usr/sbin/pkg install sudo
echo 'y' | /usr/sbin/pkg install nano
echo 'y' | /usr/sbin/pkg install rsync
echo 'y' | /usr/sbin/pkg install net-snmp
echo 'y' | /usr/sbin/pkg install php56-openssl

else
    echo "pfSense Version Unsupported. Supported Version: pfSense 2.3.x"
    exit
fi

##### Global Variables #####

FILE="/cf/conf/config.xml"
XMLS=$(which xml)

read -p 'Enter this devices Ubersmith device id (ex: 22-1143)  : ' hostname
read -p 'Enter WAN Server IP Address and Subnet(ex: 209.208.18.98/30) : ' wanrange
read -p 'Enter WAN Server Gateway Address(ex: 209.208.18.97) : ' wangate
read -p 'Enter LAN IP Range and Subnet(ex: 192.168.0.0/24)  : ' lannet
read -p 'Set LAN Interface IP(ex: 192.168.0.1)  : ' lanintnet
read -p 'Enter VPN range (ex: 10.10.34.128/25)  : ' vpnpool
read -p 'Enter Distinguished name for VPN (ex: Atlanticnet) : ' dname
read -p 'Enter Pre-Shared Key (At least 56 character password)  : ' PSK
read -p 'Enter the SNMP Community String : ' id
read -p 'Does this order include an IDS server? (yes or no) : ' idsinstall

##### Defining Variables #####

WANIP=$(echo $wanrange | awk -F'/' '{print $1}')
WANCIDR=$(echo $wanrange | awk -F'/' '{print $2}')

LANINTIP=$(echo $lanintnet | awk -F'/' '{print $1}')
LANINTCIDR=$(echo $lannet | awk -F'/' '{print $2}')
LANRANGE=$(echo $lannet | awk -F'-' '{print $1}')

VPNIP=$(echo $vpnpool | awk -F'/' '{print $1}')
VPNIPNET=$(echo $vpnpool | awk -F'/' '{print $2}')
VPNRANGE=$(echo $vpnpool | awk -F'-' '{print $1}')

FQDN=$(echo $dname | awk -F'/' '{print $1}')
PSK=$(echo "$PSK" | sed 's/&/\\&amp;/')

##### Gather interface mapping #####
wanint=$(cat ${FILE} | grep -A2 '<wan>' | grep 'if' | awk -F'<' '{print $2}' | awk -F'>' '{print $2}')
lanint=$(cat ${FILE} | grep -A2 '<lan>' | grep 'if' | awk -F'<' '{print $2}' | awk -F'>' '{print $2}')

####################################
# Inject Role_NOC_Tier_2 & 3 group #
####################################

echo 'Role_NOC_Tier_3:*:2011:root' >> /etc/group
echo 'Role_NOC_Tier_2:*:2012:root' >> /etc/group

######################
# Adding Sysctl node #
######################

# echo
# echo "Adding Sysctl Node..."

# $XMLS ed --inplace --subnode /pfsense --type elem -n sysctl --value "" ${FILE}

# echo "Sysctl Node Added!"
# echo

# sleep 2;

##### Functions #####

#############################################################
# Counting strings to see if another node needs to be added #
#############################################################

count_item_strings()
{
ITEM_COUNT=$($XMLS sel -t -v "count(/pfsense/sysctl/item)" ${FILE})
ITEM_NEED=31

if [ "$ITEM_COUNT" -lt "$ITEM_NEED" ]; then

 $XMLS ed --inplace --subnode /pfsense/sysctl --type elem -n item --value "" ${FILE}

fi
}

count_group_strings()
{
ITEM_COUNT=$($XMLS sel -t -v "count(/pfsense/system/group)" ${FILE})
ITEM_NEED=4

if [ "$ITEM_COUNT" -lt "$ITEM_NEED" ]; then

 $XMLS ed --inplace --subnode /pfsense/system --type elem -n group --value "" ${FILE}

fi
}

count_user_strings()
{
ITEM_COUNT=$($XMLS sel -t -v "count(/pfsense/system/user)" ${FILE})
ITEM_NEED=2

if [ "$ITEM_COUNT" -lt "$ITEM_NEED" ]; then

 $XMLS ed --inplace --subnode /pfsense/system --type elem -n user --value "" ${FILE}

fi
}

count_dnsserver_strings()
{
ITEM_COUNT=$($XMLS sel -t -v "count(/pfsense/system/dnsserver)" ${FILE})
ITEM_NEED=2

if [ "$ITEM_COUNT" -lt "$ITEM_NEED" ]; then

 $XMLS ed --inplace --subnode /pfsense/system --type elem -n dnsserver --value "" ${FILE}

fi
}

count_rule_strings()
{
ITEM_COUNT=$($XMLS sel -t -v "count(/pfsense/filter/rule)" ${FILE})
ITEM_NEED=10

if [ "$ITEM_COUNT" -lt "$ITEM_NEED" ]; then

 $XMLS ed --inplace --subnode /pfsense/filter --type elem -n rule --value "" ${FILE}

fi
}

count_alias_strings()
{
ITEM_COUNT=$($XMLS sel -t -v "count(/pfsense/aliases/alias)" ${FILE})
ITEM_NEED=5

if [ "$ITEM_COUNT" -lt "$ITEM_NEED" ]; then

 $XMLS ed --inplace --subnode /pfsense/aliases --type elem -n alias --value "" ${FILE}

fi
}

count_nat_rule_strings()
{
ITEM_COUNT=$($XMLS sel -t -v "count(/pfsense/nat/outbound/rule)" ${FILE})
ITEM_NEED=2

if [ "$ITEM_COUNT" -lt "$ITEM_NEED" ]; then

 $XMLS ed --inplace --subnode /pfsense/nat/outbound --type elem -n rule --value "" ${FILE}

fi
}

count_portforward_rule_strings()
{
ITEM_COUNT=$($XMLS sel -t -v "count(/pfsense/nat/rule)" ${FILE})
ITEM_NEED=4

if [ "$ITEM_COUNT" -lt "$ITEM_NEED" ]; then

 $XMLS ed --inplace --subnode /pfsense/nat --type elem -n rule --value "" ${FILE}

fi
}
count_cron_item_strings()
{
ITEM_COUNT=$($XMLS sel -t -v "count(pfsense/cron/item)" ${FILE})
ITEM_NEED=9

if [ "$ITEM_COUNT" -lt "$ITEM_NEED" ]; then

 $XMLS ed --inplace --subnode /pfsense/cron --type elem -n item --value "" ${FILE}

fi
}

add_wildcard_cert()
{
	$XMLS ed --inplace --subnode /pfsense --type elem -n cert --value "" ${FILE}
}

cert_config()
{
	NUMBER=$1
	NAME=$2
	VALUE=$3
	xml ed --inplace --subnode /pfsense/cert[$NUMBER] --type elem -n $NAME -v "$VALUE" ${FILE}
}

####################################
# Adding Item elements with values #
####################################

xml_insert_element()
{
        NUMBER=$1
        NAME=$2
        VALUE=$3
        xml ed --inplace --subnode /pfsense/sysctl/item[$NUMBER] --type elem -n $NAME -v "$VALUE" ${FILE}
}

#####################################
# Adding group elements with values #
#####################################

xml_group_element()
{
        NUMBER=$1
        NAME=$2
        VALUE="$3"
        xml ed --inplace --subnode /pfsense/system/group[$NUMBER] --type elem -n $NAME -v "$VALUE" ${FILE}
}

#########################
# Updating/Adding Users #
#########################

update_users()
{
	NUMBER=$1
	NAME=$2
	VALUE="$3"
	xml ed --inplace --subnode /pfsense/system/user[$NUMBER] --type elem -n $NAME -v "$VALUE" ${FILE}
}

update_password()
{
	NUMBER=$1
	xml ed --inplace --delete /pfsense/system/user[$NUMBER]/password ${FILE}
	xml ed --inplace --update /pfsense/system/user[$NUMBER]/bcrypt-hash --value "$rootpass" ${FILE}
}

############################
# Updating System Settings #
############################

update_settings()
{
    xml ed --inplace --update /pfsense/system/nextuid --value "2001" ${FILE}
    xml ed --inplace --update /pfsense/system/nextgid --value "2013" ${FILE}
	xml ed --inplace --update /pfsense/system/time-update-interval --value '' ${FILE}
	xml ed --inplace --delete /pfsense/system/disablenatreflection ${FILE}
	xml ed --inplace --delete /pfsense/system/ipv6allow ${FILE}
	xml ed --inplace --delete /pfsense/system/powerd_normal_mode ${FILE}
	xml ed --inplace --delete /pfsense/unbound ${FILE}
}

#####################
# Add SSL to WebGUI #
#####################

add_ssl()
{
        NAME=$1
        VALUE=$2
	xml ed --inplace --update /pfsense/system/webgui/ssl-certref --value "591cb9c537fad" ${FILE}
	xml ed --inplace --update /pfsense/system/webgui/max_procs --value "5" ${FILE}
	xml ed --inplace --subnode /pfsense/system/webgui --type elem -n $NAME -v "$VALUE" ${FILE}
}

########################
# More System Settings #
########################

more_settings()
{
	NAME=$1
        VALUE=$2
	xml ed --inplace --subnode /pfsense/system --type elem -n $NAME -v "$VALUE" ${FILE}
}

side_settings()
{
	NAME=$1
        VALUE=$2
	xml ed --inplace --update /pfsense/system/dnsserver[$NAME] --value "$VALUE" ${FILE}
}

authserver_settings()
{
	NAME=$1
        VALUE=$2
        xml ed --inplace --subnode /pfsense/system/authserver --type elem -n $NAME -v "$VALUE" ${FILE}
}

#########################
# Setting Up Interfaces #
#########################

wan_settings()
{
	NAME=$1
        VALUE=$2
        # xml ed --inplace --subnode /pfsense/interfaces/wan --type elem -n $NAME -v "$VALUE" ${FILE}
	xml ed --inplace --update /pfsense/interfaces/wan/ipaddr --value "$WANIP" ${FILE}
	xml ed --inplace --update /pfsense/interfaces/wan/subnet --value "$WANCIDR" ${FILE}
	xml ed --inplace --update /pfsense/interfaces/wan/gateway --value "GW_WAN" ${FILE}
	# xml ed --inplace --delete /pfsense/interfaces/wan/blockpriv ${FILE}
	# xml ed --inplace --delete /pfsense/interfaces/wan/blockbogons ${FILE}
	# xml ed --inplace --delete /pfsense/interfaces/wan/dhcphostname ${FILE}
	# xml ed --inplace --delete /pfsense/interfaces/wan/media ${FILE}
	# xml ed --inplace --delete /pfsense/interfaces/wan/mediaopt ${FILE}
	# xml ed --inplace --delete /pfsense/interfaces/wan/dhcp6-duid ${FILE}
	# xml ed --inplace --delete /pfsense/interfaces/wan/dhcp6-ia-pd-len ${FILE}
	# xml ed --inplace --delete /pfsense/interfaces/wan/subnetv6 ${FILE}
	# xml ed --inplace --delete /pfsense/interfaces/wan/gatewayv6 ${FILE}
}

wan_gateway()
{
	xml ed --inplace --subnode /pfsense/system/gateways --type elem -n gateway_item -v "" ${FILE}
}

wan_gateway_settings()
{
	xml ed --inplace --update /pfsense/gateways/gateway_item/gateway --value "$wangate" ${FILE}
}

lan_settings()
{
	NAME=$1
        VALUE=$2
        # xml ed --inplace --subnode /pfsense/interfaces/lan --type elem -n $NAME -v "$VALUE" ${FILE}
	xml ed --inplace --update /pfsense/interfaces/lan/ipaddr --value "$LANINTIP" ${FILE}
	xml ed --inplace --update /pfsense/interfaces/lan/subnet --value "$LANINTCIDR" ${FILE}
	# xml ed --inplace --delete /pfsense/interfaces/lan/ipaddrv6 ${FILE}
	# xml ed --inplace --delete /pfsense/interfaces/lan/subnetv6 ${FILE}
	# xml ed --inplace --delete /pfsense/interfaces/lan/media ${FILE}
	# xml ed --inplace --delete /pfsense/interfaces/lan/mediaopt ${FILE}
	# xml ed --inplace --delete /pfsense/interfaces/lan/track6-interface ${FILE}
	# xml ed --inplace --delete /pfsense/interfaces/lan/track6-prefix-id ${FILE}
}

backup_settings()
{
	NAME=$1
	VALUE=$2
	# xml ed --inplace --subnode /pfsense/interfaces/opt1 --type elem -n $NAME -v "$VALUE" ${FILE}
	# xml ed --inplace --update /pfsense/interfaces/opt1/descr --value "BACKUP" ${FILE}
	xml ed --inplace --update /pfsense/interfaces/opt1/ipaddr --value "$BAKINTIP" ${FILE}
	xml ed --inplace --update /pfsense/interfaces/opt1/subnet --value "$BAKINTCIDR" ${FILE}
	}

#################
# Removing DHCP #
#################

dhcp_removal()
{
        xml ed --inplace --update /pfsense/dhcpd --value "" ${FILE}
}

####################
# Enabling DNSMasq #
####################

dnsmasq_enable()
{
	NAME=$1
        VALUE=$2
	xml ed --inplace --subnode /pfsense --type elem -n dnsmasq -v "" ${FILE}
	xml ed --inplace --subnode /pfsense/dnsmasq --type elem -n $NAME -v "" ${FILE}
}

snmpd_settings()
{
	NAME=$1
        VALUE=$2
	# xml ed --inplace --update /pfsense/snmpd/syslocation --value "Orlando data center" ${FILE}
	# xml ed --inplace --update /pfsense/snmpd/syscontact --value "device-alerts@atlantic.net" ${FILE}
	xml ed --inplace --update /pfsense/snmpd/rocommunity --value "$id" ${FILE}
	xml ed --inplace --subnode /pfsense/snmpd --type elem -n $NAME -v "$VALUE" ${FILE}
}

snmpd_modules()
{
	NAME=$1
	VALUE=$2
	xml ed --inplace --subnode /pfsense/snmpd/modules --type elem -n $NAME -v "$VALUE" ${FILE}
}

diag_setting()
{
	xml ed --inplace --update /pfsense/diag/ipv6nat --value "" ${FILE}
}

#############
# NAT Rules #
#############

nat_settings()
{
	NAME=$1
        VALUE=$2
        xml ed --inplace --subnode /pfsense --type elem -n nat -v "" ${FILE}
		xml ed --inplace --subnode /pfsense/nat --type elem -n outbound -v "" ${FILE}
        xml ed --inplace --subnode /pfsense/nat/outbound --type elem -n $NAME -v "$VALUE" ${FILE}
}

portforward_rules()
{
        NUMBER=$1
        NAME=$2
        VALUE="$3"
        xml ed --inplace --subnode /pfsense/nat/rule[$NUMBER] --type elem -n $NAME -v "$VALUE" ${FILE}
}

portforward_source_rule()
{
        NUMBER=$1
        NAME=$2
        VALUE="$3"
	RULE=$4
        xml ed --inplace --subnode /pfsense/nat/rule[$RULE]/source[$NUMBER] --type elem -n $NAME -v "$VALUE" ${FILE}
}

portforward_destination_rule()
{
        NUMBER=$1
        NAME=$2
        VALUE="$3"
	RULE=$4
        xml ed --inplace --subnode /pfsense/nat/rule[$RULE]/destination[$NUMBER] --type elem -n $NAME -v "$VALUE" ${FILE}
}

portforward_updated()
{
        NUMBER=$1
        NAME=$2
        VALUE="$3"
	RULE=$4
        xml ed --inplace --subnode /pfsense/nat/rule[$RULE]/updated[$NUMBER] --type elem -n $NAME -v "$VALUE" ${FILE}
}

portforward_created()
{
        NUMBER=$1
        NAME=$2
        VALUE="$3"
	RULE=$4
        xml ed --inplace --subnode /pfsense/nat/rule[$RULE]/created[$NUMBER] --type elem -n $NAME -v "$VALUE" ${FILE}
}
###########################
# Adding/Editing FW Rules #
###########################

adding_rules()
{
	NUMBER=$1
        NAME=$2
        VALUE="$3"
        xml ed --inplace --subnode /pfsense/filter/rule[$NUMBER] --type elem -n $NAME -v "$VALUE" ${FILE}
}

editing_source_address()
{
	NUMBER=$1
        NAME=$2
	VALUE=$3
	RULE=$4
	xml ed --inplace --subnode /pfsense/filter/rule[$RULE]/source[$NUMBER] --type elem -n $NAME -v "$VALUE" ${FILE}	
}

editing_destination_address()
{
        NUMBER=$1
        NAME=$2
        VALUE=$3
	RULE=$4
        xml ed --inplace --subnode /pfsense/filter/rule[$RULE]/destination[$NUMBER] --type elem -n $NAME -v "$VALUE" ${FILE}
}

editing_updated()
{
	NUMBER=$1
        NAME=$2
        VALUE=$3
	RULE=$4
        xml ed --inplace --subnode /pfsense/filter/rule[$RULE]/updated[$NUMBER] --type elem -n $NAME -v "$VALUE" ${FILE}
}

editing_created()
{
	NUMBER=$1
        NAME=$2
        VALUE=$3
	RULE=$4
        xml ed --inplace --subnode /pfsense/filter/rule[$RULE]/created[$NUMBER] --type elem -n $NAME -v "$VALUE" ${FILE}
}

update_rules()
{
	NUMBER=$1
        VALUE=$2
        RULE=$3
        xml ed --inplace --update /pfsense/filter/rule[$RULE]/tracker[$NUMBER] --value "$VALUE" ${FILE}
}

###############################
# Setting Up IPSec with Rules #
###############################

add_ipsec_node()
{
	xml ed --inplace --subnode /pfsense --type elem -n ipsec --value "" ${FILE}
}

configuring_ipsec_nodes()
{
	NUMBER=$1
        NAME=$2
        VALUE=$3
	xml ed --inplace --subnode /pfsense/ipsec --type elem -n enable --value "" ${FILE}
	xml ed --inplace --subnode /pfsense/ipsec --type elem -n client --value "" ${FILE}
	xml ed --inplace --subnode /pfsense/ipsec --type elem -n phase1 --value "" ${FILE}
	xml ed --inplace --subnode /pfsense/ipsec --type elem -n phase2 --value "" ${FILE}
	xml ed --inplace --subnode /pfsense/ipsec --type elem -n unityplugin --value "" ${FILE}
}

configuring_ipsec_client()
{
	NUMBER=$1
        NAME=$2
        VALUE=$3
	xml ed --inplace --subnode /pfsense/ipsec/client[$NUMBER] --type elem -n $NAME --value "$VALUE" ${FILE}
}

configuring_ipsec_phase1()
{
	NUMBER=$1
        NAME=$2
        VALUE=$3
        xml ed --inplace --subnode /pfsense/ipsec/phase1[$NUMBER] --type elem -n $NAME --value "$VALUE" ${FILE}
}

configuring_ipsec_phase2()
{
        NUMBER=$1
        NAME=$2
        VALUE=$3
        xml ed --inplace --subnode /pfsense/ipsec/phase2[$NUMBER] --type elem -n $NAME --value "$VALUE" ${FILE}
}

editing_phase1_encryption()
{
	NUMBER=$1
        NAME=$2
        VALUE=$3
        xml ed --inplace --subnode /pfsense/ipsec/phase1/encryption-algorithm[$NUMBER] --type elem -n $NAME --value "$VALUE" ${FILE}
}

editing_phase2_localid()
{
	NUMBER=$1
        NAME=$2
        VALUE=$3
        xml ed --inplace --subnode /pfsense/ipsec/phase2/localid[$NUMBER] --type elem -n $NAME --value "$VALUE" ${FILE}
}

editing_phase2_remoteid()
{
        NUMBER=$1
        NAME=$2
        VALUE=$3
        xml ed --inplace --subnode /pfsense/ipsec/phase2/remoteid[$NUMBER] --type elem -n $NAME --value "$VALUE" ${FILE}
}

editing_encryption_algorithm()
{
        NUMBER=$1
        NAME=$2
        VALUE=$3
        xml ed --inplace --subnode /pfsense/ipsec/phase2/encryption-algorithm-option[$NUMBER] --type elem -n $NAME --value "$VALUE" ${FILE}
}

adding_aliases()
{
	NUMBER=$1
        NAME=$2
        VALUE=$3
	xml ed --inplace --update /pfsense/aliases/alias[$NUMBER]/$NAME --value "$VALUE" ${FILE}
}

###########################
# Setting up Outbount NAT #
###########################

outbound_nat()
{
	NUMBER=$1
        NAME=$2
        VALUE=$3
	xml ed --inplace --update /pfsense/nat/outbound/mode --value "hybrid" ${FILE}	
	xml ed --inplace --subnode /pfsense/nat/outbound/rule[$NUMBER] --type elem -n $NAME --value "$VALUE" ${FILE}
}

editing_nat_source()
{
	NUMBER=$1
        NAME=$2
        VALUE=$3
	RULE=$4
	xml ed --inplace --subnode /pfsense/nat/outbound/rule[$RULE]/source[$NUMBER] --type elem -n $NAME -v "$VALUE" ${FILE}
}

editing_nat_destination()
{
        NUMBER=$1
        NAME=$2
        VALUE=$3
        RULE=$4
        xml ed --inplace --subnode /pfsense/nat/outbound/rule[$RULE]/destination[$NUMBER] --type elem -n $NAME -v "$VALUE" ${FILE}
}

editing_nat_updated()
{
        NUMBER=$1
        NAME=$2
        VALUE=$3
        RULE=$4
        xml ed --inplace --subnode /pfsense/nat/outbound/rule[$RULE]/updated[$NUMBER] --type elem -n $NAME -v "$VALUE" ${FILE}
}

editing_nat_created()
{
        NUMBER=$1
        NAME=$2
        VALUE=$3
        RULE=$4
        xml ed --inplace --subnode /pfsense/nat/outbound/rule[$RULE]/created[$NUMBER] --type elem -n $NAME -v "$VALUE" ${FILE}
}

######################
# Additional Changes #
######################

edit_cron_item_strings()
{
	NUMBER=$1
        NAME=$2
        VALUE=$3
        xml ed --inplace --subnode /pfsense/cron/item[$NUMBER] --type elem -n $NAME -v "$VALUE" ${FILE}
}	

edit_widgets()
{
	xml ed --inplace --update /pfsense/widgets/sequence --value "system_information:col1:open,installed_packages:col1:open,interfaces:col2:open,smart_status:col2:open,gmirror_status:col2:open,ipsec:col2:open,openvpn:col2:open,load_balancer_status:col2:open,services_status:col2:open" ${FILE}
}

########################
# Adding Notifications #
########################

add_notifications()
{
	$XMLS ed --inplace --subnode /pfsense --type elem -n notifications --value "" ${FILE}
	$XMLS ed --inplace --subnode /pfsense/notifications --type elem -n growl --value "" ${FILE}
	$XMLS ed --inplace --subnode /pfsense/notifications --type elem -n smtp --value "" ${FILE}
}

edit_growl_notifications()
{
	NAME=$1
        VALUE=$2
        xml ed --inplace --subnode /pfsense/notifications/growl --type elem -n $NAME -v "$VALUE" ${FILE}
}

edit_smtp_notifications()
{
        NAME=$1
        VALUE=$2
        xml ed --inplace --subnode /pfsense/notifications/smtp --type elem -n $NAME -v "$VALUE" ${FILE}
}

edit_hostname()
{
	xml ed --inplace --update /pfsense/system/hostname --value "$hostname" ${FILE}
	xml ed --inplace --update /pfsense/system/domain --value "atlantic.net" ${FILE}
}

installing_snort()
{
echo "Installing IDS (this can take up to 5 minutes to complete)..."

read -p 'Set IDS IP(ex: 10.18.34.2)  : ' idsintip
read -p 'Enter the barnyard password (Same as pfsense root password)  : ' bypwd

IDSIP=$(echo $idsintip | awk -F'/' '{print $1}')
BYARDPWD=$(echo -n $bypwd | openssl base64)

#################
# Install Snort #
#################

/usr/local/sbin/pfSsh.php playback installpkg "snort"

#### Functions ####

################
# Adding Nodes #
################

############################
# Snort Port Forward Rules #
############################

ids_nat()
{
	xml ed --inplace --update /pfsense/filter/rule[10]/destination/address --value "$IDSIP" ${FILE}
}

###############################
# Editing Snort Configuration #
###############################

edit_snort_configurations()
{
        NAME=$1
        VALUE=$2
        xml ed --inplace --subnode /pfsense/installedpackages/snortglobal --type elem -n $NAME -v "$VALUE" ${FILE}
}

edit_snort_rule()
{
	NAME=$1
        VALUE=$2
        xml ed --inplace --subnode /pfsense/installedpackages/snortglobal/rule --type elem -n $NAME -v "$VALUE" ${FILE}
}

edit_engine_rules()
{
        NODE=$1
	NAME=$2
        xml ed --inplace --subnode /pfsense/installedpackages/snortglobal/rule/$NODE --type elem -n $NAME -v "" ${FILE}
}

edit_engine_item_rules()
{
        NODE=$1
        NAME=$2
	VALUE=$3
        xml ed --inplace --subnode /pfsense/installedpackages/snortglobal/rule/$NODE/item --type elem -n $NAME -v "$VALUE" ${FILE}
}

#### Snort Main Script ####

echo "Adding IDS WEB GUI rule..."

count_rule_strings

adding_rules 10 interface wan
adding_rules 10 protocol tcp
adding_rules 10 source

editing_source_address 1 any "" 10

adding_rules 10 destination 

editing_destination_address 1 address "$IDSIP" 10
editing_destination_address 1 port 3000 10

ids_nat

adding_rules 10 descr "NAT IDS WEB GUI"
adding_rules 10 associated-rule-id "nat_58481fb8dd5f13.14595144"
adding_rules 10 created

editing_created 1 time "1481121720" 10
editing_created 1 username "NAT Port Forward" 10

echo "IDS WEB GUI rule added"
echo

sleep 1;

echo "Adding IDS Port Forwards..."

count_portforward_rule_strings

portforward_rules 1 source 

portforward_source_rule 1 any "" 1

portforward_rules 1 destination

portforward_destination_rule 1 network wanip 1
portforward_destination_rule 1 port 222 1

portforward_rules 1 protocol tcp
portforward_rules 1 target "$IDSIP"
portforward_rules 1 local-port 22
portforward_rules 1 interface wan
portforward_rules 1 descr "IDS SSH"
portforward_rules 1 associated-rule-id 
portforward_rules 1 updated

portforward_updated 1 time "1481121360" 1
portforward_updated 1 username "rleon@209.208.0.193" 1

portforward_rules 1 created

portforward_created 1 time "1481121360" 1
portforward_created 1 username "rleon@209.208.0.193" 1

count_portforward_rule_strings

portforward_rules 2 source

portforward_source_rule 1 any "" 2

portforward_rules 2 destination

portforward_destination_rule 1 network wanip 2
portforward_destination_rule 1 port 3000 2

portforward_rules 2 protocol tcp
portforward_rules 2 target "$IDSIP"
portforward_rules 2 local-port 3000
portforward_rules 2 interface wan
portforward_rules 2 descr "IDS WEB GUI"
portforward_rules 2 associated-rule-id
portforward_rules 2 updated

portforward_updated 1 time "1481121720" 2
portforward_updated 1 username "rleon@209.208.0.193" 2

portforward_rules 2 created

portforward_created 1 time "1481121720" 2
portforward_created 1 username "rleon@209.208.0.193" 2

count_portforward_rule_strings

portforward_rules 3 source

portforward_source_rule 1 any "" 3

portforward_rules 3 destination

portforward_destination_rule 1 network wanip 3
portforward_destination_rule 1 port 1161 3

portforward_rules 3 protocol udp
portforward_rules 3 target "$IDSIP"
portforward_rules 3 local-port 161
portforward_rules 3 interface wan
portforward_rules 3 descr "IDS SNMP"
portforward_rules 3 associated-rule-id
portforward_rules 3 updated

portforward_updated 1 time "1481122097" 3
portforward_updated 1 username "rleon@209.208.0.193" 3

portforward_rules 3 created

portforward_created 1 time "1481122097" 3
portforward_created 1 username "rleon@209.208.0.193" 3

echo "Done adding IDS Port Forwards"
echo

count_cron_item_strings

edit_cron_item_strings 9 minute "*/5"
edit_cron_item_strings 9 hour "*"
edit_cron_item_strings 9 mday "*"
edit_cron_item_strings 9 month "*"
edit_cron_item_strings 9 wday "*"
edit_cron_item_strings 9 who root
edit_cron_item_strings 9 command "/usr/bin/nice -n20 /usr/local/bin/php -f /usr/local/pkg/snort/snort_check_cron_misc.inc"

edit_snort_configurations snortdownload on
edit_snort_configurations snortcommunityrules on
edit_snort_configurations emergingthreats on
edit_snort_configurations emergingthreats_pro off
edit_snort_configurations clearblocks off
edit_snort_configurations verbose_logging off
edit_snort_configurations openappid_detectors off
edit_snort_configurations openappid_rules_detectors off
edit_snort_configurations hide_deprecated_rules off
edit_snort_configurations curl_no_verify_ssl_peer off
edit_snort_configurations oinkmastercode "9d7437a53f5d5f86651aea733ad535a3f417fc30"
edit_snort_configurations etpro_code
edit_snort_configurations rm_blocked never_b
edit_snort_configurations autorulesupdate7 never_up
edit_snort_configurations forcekeepsettings on
edit_snort_configurations rule

edit_snort_rule interface wan
edit_snort_rule enable on
edit_snort_rule uuid 33145
edit_snort_rule descr WAN
edit_snort_rule performance ac-bnfa
edit_snort_rule blockoffenders7 off
edit_snort_rule blockoffenderskill on
edit_snort_rule blockoffendersip both
edit_snort_rule whitelistname default
edit_snort_rule homelistname default
edit_snort_rule externallistname default
edit_snort_rule suppresslistname default
edit_snort_rule alertsystemlog off
edit_snort_rule alertsystemlog_facility log_auth
edit_snort_rule alertsystemlog_priority log_alert
edit_snort_rule cksumcheck off
edit_snort_rule fpm_split_any_any off
edit_snort_rule fpm_search_optimize off
edit_snort_rule fpm_no_stream_inserts off
edit_snort_rule max_attribute_hosts 10000
edit_snort_rule max_attribute_services_per_host 10
edit_snort_rule max_paf 16000
edit_snort_rule ftp_preprocessor on
edit_snort_rule ftp_telnet_inspection_type stateful
edit_snort_rule ftp_telnet_alert_encrypted off
edit_snort_rule ftp_telnet_check_encrypted on
edit_snort_rule ftp_telnet_normalize on
edit_snort_rule ftp_telnet_detect_anomalies on
edit_snort_rule ftp_telnet_ayt_attack_threshold 20
edit_snort_rule ftp_client_engine

edit_engine_rules ftp_client_engine item

edit_engine_item_rules ftp_client_engine name default
edit_engine_item_rules ftp_client_engine bind_to all
edit_engine_item_rules ftp_client_engine max_resp_len 256
edit_engine_item_rules ftp_client_engine telnet_cmds no
edit_engine_item_rules ftp_client_engine ignore_telnet_erase_cmds yes
edit_engine_item_rules ftp_client_engine bounce yes
edit_engine_item_rules ftp_client_engine bounce_to_net
edit_engine_item_rules ftp_client_engine bounce_to_port

edit_snort_rule ftp_server_engine

edit_engine_rules ftp_server_engine item

edit_engine_item_rules ftp_server_engine name default
edit_engine_item_rules ftp_server_engine bind_to all
edit_engine_item_rules ftp_server_engine ports default
edit_engine_item_rules ftp_server_engine telnet_cmds no
edit_engine_item_rules ftp_server_engine ignore_telnet_erase_cmds yes
edit_engine_item_rules ftp_server_engine ignore_data_chan no
edit_engine_item_rules ftp_server_engine def_max_param_len 100

edit_snort_rule smtp_preprocessor on
edit_snort_rule smtp_memcap 838860
edit_snort_rule smtp_max_mime_mem 838860
edit_snort_rule smtp_b64_decode_depth 0
edit_snort_rule smtp_qp_decode_depth 0
edit_snort_rule smtp_bitenc_decode_depth 0
edit_snort_rule smtp_uu_decode_depth 0
edit_snort_rule smtp_email_hdrs_log_depth 1464
edit_snort_rule smtp_ignore_data off
edit_snort_rule smtp_ignore_tls_data on
edit_snort_rule smtp_log_mail_from on
edit_snort_rule smtp_log_rcpt_to on
edit_snort_rule smtp_log_filename on
edit_snort_rule smtp_log_email_hdrs on
edit_snort_rule dce_rpc_2 on
edit_snort_rule dns_preprocessor on
edit_snort_rule ssl_preproc on
edit_snort_rule pop_preproc on
edit_snort_rule pop_memcap 838860
edit_snort_rule pop_b64_decode_depth 0
edit_snort_rule pop_qp_decode_depth 0
edit_snort_rule pop_bitenc_decode_depth 0
edit_snort_rule pop_uu_decode_depth 0
edit_snort_rule imap_preproc on
edit_snort_rule imap_memcap 838860
edit_snort_rule imap_b64_decode_depth 0
edit_snort_rule imap_qp_decode_depth 0
edit_snort_rule imap_bitenc_decode_depth 0
edit_snort_rule imap_uu_decode_depth 0
edit_snort_rule sip_preproc on
edit_snort_rule other_preprocs on
edit_snort_rule pscan_protocol all
edit_snort_rule pscan_type all
edit_snort_rule pscan_memcap 10000000
edit_snort_rule pscan_sense_level medium
edit_snort_rule http_inspect on
edit_snort_rule http_inspect_proxy_alert off
edit_snort_rule http_inspect_memcap 150994944
edit_snort_rule http_inspect_max_gzip_mem 838860
edit_snort_rule http_inspect_engine

edit_engine_rules http_inspect_engine item

edit_engine_item_rules http_inspect_engine name default
edit_engine_item_rules http_inspect_engine bind_to all
edit_engine_item_rules http_inspect_engine server_profile all
edit_engine_item_rules http_inspect_engine enable_xff off
edit_engine_item_rules http_inspect_engine log_uri off
edit_engine_item_rules http_inspect_engine log_hostname off
edit_engine_item_rules http_inspect_engine server_flow_depth 65535
edit_engine_item_rules http_inspect_engine enable_cookie on
edit_engine_item_rules http_inspect_engine client_flow_depth 1460
edit_engine_item_rules http_inspect_engine extended_response_inspection on
edit_engine_item_rules http_inspect_engine no_alerts off
edit_engine_item_rules http_inspect_engine unlimited_decompress on
edit_engine_item_rules http_inspect_engine inspect_gzip on
edit_engine_item_rules http_inspect_engine normalize_cookies on
edit_engine_item_rules http_inspect_engine normalize_headers on
edit_engine_item_rules http_inspect_engine normalize_utf on
edit_engine_item_rules http_inspect_engine normalize_javascript on
edit_engine_item_rules http_inspect_engine allow_proxy_use off
edit_engine_item_rules http_inspect_engine inspect_uri_only off
edit_engine_item_rules http_inspect_engine max_javascript_whitespaces 200
edit_engine_item_rules http_inspect_engine post_depth "-1"
edit_engine_item_rules http_inspect_engine max_headers 0
edit_engine_item_rules http_inspect_engine max_spaces 0
edit_engine_item_rules http_inspect_engine max_header_length 0
edit_engine_item_rules http_inspect_engine ports default
edit_engine_item_rules http_inspect_engine decompress_swf off
edit_engine_item_rules http_inspect_engine decompress_pdf off

edit_snort_rule frag3_max_frags 8192
edit_snort_rule frag3_memcap 4194304
edit_snort_rule frag3_detection on
edit_snort_rule frag3_engine

edit_engine_rules frag3_engine item

edit_engine_item_rules frag3_engine name default
edit_engine_item_rules frag3_engine bind_to all
edit_engine_item_rules frag3_engine policy bsd
edit_engine_item_rules frag3_engine timeout 60
edit_engine_item_rules frag3_engine min_ttl 1
edit_engine_item_rules frag3_engine detect_anomalies on
edit_engine_item_rules frag3_engine overlap_limit 0
edit_engine_item_rules frag3_engine min_frag_len 0

edit_snort_rule stream5_reassembly on
edit_snort_rule stream5_flush_on_alert off
edit_snort_rule stream5_prune_log_max 1048576
edit_snort_rule stream5_track_tcp on
edit_snort_rule stream5_max_tcp 262144
edit_snort_rule stream5_track_udp on
edit_snort_rule stream5_max_udp 131072
edit_snort_rule stream5_udp_timeout 30
edit_snort_rule stream5_track_icmp off
edit_snort_rule stream5_max_icmp 65536
edit_snort_rule stream5_icmp_timeout 30
edit_snort_rule stream5_mem_cap 838860
edit_snort_rule stream5_tcp_engine

edit_engine_rules stream5_tcp_engine item

edit_engine_item_rules stream5_tcp_engine name default
edit_engine_item_rules stream5_tcp_engine bind_to all
edit_engine_item_rules stream5_tcp_engine policy bsd
edit_engine_item_rules stream5_tcp_engine timeout 30
edit_engine_item_rules stream5_tcp_engine max_queued_bytes 1048576
edit_engine_item_rules stream5_tcp_engine detect_anomalies off
edit_engine_item_rules stream5_tcp_engine overlap_limit 0
edit_engine_item_rules stream5_tcp_engine max_queued_segs 2621
edit_engine_item_rules stream5_tcp_engine require_3whs off
edit_engine_item_rules stream5_tcp_engine startup_3whs_timeout 0
edit_engine_item_rules stream5_tcp_engine no_reassemble_async off
edit_engine_item_rules stream5_tcp_engine max_window 0
edit_engine_item_rules stream5_tcp_engine use_static_footprint_sizes off
edit_engine_item_rules stream5_tcp_engine check_session_hijacking off
edit_engine_item_rules stream5_tcp_engine dont_store_lg_pkts off
edit_engine_item_rules stream5_tcp_engine ports_client default
edit_engine_item_rules stream5_tcp_engine ports_both default
edit_engine_item_rules stream5_tcp_engine ports_server none

edit_snort_rule appid_preproc off
edit_snort_rule sf_appid_mem_cap 256
edit_snort_rule sf_appid_statslog on
edit_snort_rule sf_appid_stats_period 300
edit_snort_rule ips_policy_enable on
edit_snort_rule ips_policy balanced
edit_snort_rule rulesets
edit_snort_rule autoflowbitrules on
edit_snort_rule sdf_alert_data_type "Credit Card,Email Addresses,U.S. Phone Numbers,U.S. Social Security Numbers"
edit_snort_rule sdf_alert_threshold 25
edit_snort_rule sdf_mask_output off
edit_snort_rule ssh_preproc on
edit_snort_rule pscan_ignore_scanners
edit_snort_rule pscan_ignore_scanned
edit_snort_rule perform_stat off
edit_snort_rule host_attribute_table off
edit_snort_rule sf_portscan on
edit_snort_rule sensitive_data off
edit_snort_rule dnp3_preproc off
edit_snort_rule modbus_preproc off
edit_snort_rule gtp_preproc off
edit_snort_rule preproc_auto_rule_disable off
edit_snort_rule protect_preproc_rules off
edit_snort_rule barnyard_show_year on
edit_snort_rule unified2_log_limit 128K
edit_snort_rule barnyard_archive_enable on
edit_snort_rule u2_archived_log_retention 168
edit_snort_rule barnyard_obfuscate_ip off
edit_snort_rule barnyard_syslog_dport 514
edit_snort_rule barnyard_syslog_proto udp
edit_snort_rule barnyard_syslog_opmode default
edit_snort_rule barnyard_syslog_facility "LOG_USER"
edit_snort_rule barnyard_syslog_priority "LOG_INFO"
edit_snort_rule barnyard_bro_ids_dport 47760
edit_snort_rule barnyard_enable on
edit_snort_rule barnyard_dump_payload off
edit_snort_rule barnyard_log_vlan_events off
edit_snort_rule barnyard_log_mpls_events off
edit_snort_rule barnyard_mysql_enable on
edit_snort_rule barnyard_syslog_enable off
edit_snort_rule barnyard_syslog_local off
edit_snort_rule barnyard_bro_ids_enable off
edit_snort_rule barnyard_disable_sig_ref_tbl off
edit_snort_rule barnyard_dbhost "$IDSIP"
edit_snort_rule barnyard_dbname snorby
edit_snort_rule barnyard_dbuser snort
edit_snort_rule barnyard_dbpwd barnpassword

#########################
# Add Barnyard Password # 
#########################

sed -i '' "s/barnpassword/${BYARDPWD}/" ${FILE}

}

update_snort_rules()
{
##############################
# Add Snort Rules and Update #
##############################

echo "Updating Snort Rules.....(this can take a few minutes)"

/usr/local/bin/php-cgi -f /usr/local/pkg/snort/snort_check_for_rule_updates.php

#sleep 180;
echo "Done Downloading Snort Rules."
}

##### Main Script #####

# count_item_strings

# echo "Adding Elements to System Tunables"

# xml_insert_element 1 descr "Enable mounting the FS read only with more checks."
# xml_insert_element 1 tunable vfs.forcesync
# xml_insert_element 1 value default

# count_item_strings

# xml_insert_element 2 descr "Disable the pf ftp proxy handler."
# xml_insert_element 2 tunable debug.pfftpproxy
# xml_insert_element 2 value default

# count_item_strings

# xml_insert_element 3 descr "Increase UFS read-ahead speeds to match current state of hard drives and NCQ. More information here: http://ivoras.sharanet.org/blog/tree/2010-11-19.ufs-read-ahead.html"
# xml_insert_element 3 tunable vfs.read_max
# xml_insert_element 3 value default

# count_item_strings

# xml_insert_element 4 descr "Set the ephemeral port range to be lower."
# xml_insert_element 4 tunable net.inet.ip.portrange.first
# xml_insert_element 4 value default

# count_item_strings

# xml_insert_element 5 descr "Drop packets to closed TCP ports without returning a RST"
# xml_insert_element 5 tunable net.inet.tcp.blackhole
# xml_insert_element 5 value default

# count_item_strings

# xml_insert_element 6 descr "Do not send ICMP port unreachable messages for closed UDP ports"
# xml_insert_element 6 tunable net.inet.udp.blackhole
# xml_insert_element 6 value default

# count_item_strings

# xml_insert_element 7 descr "Randomize the ID field in IP packets (default is 0: sequential IP IDs)"
# xml_insert_element 7 tunable net.inet.ip.random_id
# xml_insert_element 7 value default

# count_item_strings

# xml_insert_element 8 descr "Drop SYN-FIN packets (breaks RFC1379, but nobody uses it anyway)"
# xml_insert_element 8 tunable net.inet.tcp.drop_synfin
# xml_insert_element 8 value default

# count_item_strings

# xml_insert_element 9 descr "Enable sending IPv4 redirects"
# xml_insert_element 9 tunable net.inet.ip.redirect
# xml_insert_element 9 value default

# count_item_strings

# xml_insert_element 10 descr "Enable sending IPv6 redirects"
# xml_insert_element 10 tunable net.inet6.ip6.redirect
# xml_insert_element 10 value default

# count_item_strings

# xml_insert_element 11 descr "Enable privacy settings for IPv6 (RFC 4941)"
# xml_insert_element 11 tunable net.inet6.ip6.use_tempaddr
# xml_insert_element 11 value default

# count_item_strings

# xml_insert_element 12 descr "Prefer privacy addresses and use them over the normal addresses"
# xml_insert_element 12 tunable net.inet6.ip6.prefer_tempaddr
# xml_insert_element 12 value default

# count_item_strings

# xml_insert_element 13 descr "Generate SYN cookies for outbound SYN-ACK packets"
# xml_insert_element 13 tunable net.inet.tcp.syncookies
# xml_insert_element 13 value default

# count_item_strings

# xml_insert_element 14 descr "Maximum incoming/outgoing TCP datagram size (receive)"
# xml_insert_element 14 tunable net.inet.tcp.recvspace
# xml_insert_element 14 value default

# count_item_strings

# xml_insert_element 15 descr "Maximum incoming/outgoing TCP datagram size (send)"
# xml_insert_element 15 tunable net.inet.tcp.sendspace
# xml_insert_element 15 value default

# count_item_strings

# xml_insert_element 16 descr "Do not delay ACK to try and piggyback it onto a data packet"
# xml_insert_element 16 tunable net.inet.tcp.delayed_ack
# xml_insert_element 16 value default

# count_item_strings

# xml_insert_element 17 descr "Maximum outgoing UDP datagram size"
# xml_insert_element 17 tunable net.inet.udp.maxdgram
# xml_insert_element 17 value default

# count_item_strings

# xml_insert_element 18 descr "Handling of non-IP packets which are not passed to pfil (see if_bridge(4))"
# xml_insert_element 18 tunable net.link.bridge.pfil_onlyip
# xml_insert_element 18 value default

# count_item_strings

# xml_insert_element 19 descr "Set to 0 to disable filtering on the incoming and outgoing member interfaces."
# xml_insert_element 19 tunable net.link.bridge.pfil_member
# xml_insert_element 19 value default

# count_item_strings

# xml_insert_element 20 descr "Set to 1 to enable filtering on the bridge interface"
# xml_insert_element 20 tunable net.link.bridge.pfil_bridge
# xml_insert_element 20 value default

# count_item_strings

# xml_insert_element 21 descr "Allow unprivileged access to tap(4) device nodes"
# xml_insert_element 21 tunable net.link.tap.user_open
# xml_insert_element 21 value default

# count_item_strings

# xml_insert_element 22 descr "Randomize PID's (see src/sys/kern/kern_fork.c: sysctl_kern_randompid())"
# xml_insert_element 22 tunable kern.randompid
# xml_insert_element 22 value default

# count_item_strings

# xml_insert_element 23 descr "Maximum size of the IP input queue"
# xml_insert_element 23 tunable net.inet.ip.intr_queue_maxlen
# xml_insert_element 23 value default

# count_item_strings

# xml_insert_element 24 descr "Disable CTRL+ALT+Delete reboot from keyboard."
# xml_insert_element 24 tunable hw.syscons.kbd_reboot
# xml_insert_element 24 value default

# count_item_strings

# xml_insert_element 25 descr "Enable TCP Inflight mode"
# xml_insert_element 25 tunable net.inet.tcp.inflight.enable
# xml_insert_element 25 value default

# count_item_strings

# xml_insert_element 26 descr "Enable TCP extended debugging"
# xml_insert_element 26 tunable net.inet.tcp.log_debug
# xml_insert_element 26 value default

# count_item_strings

# xml_insert_element 27 descr "Set ICMP Limits"
# xml_insert_element 27 tunable net.inet.icmp.icmplim
# xml_insert_element 27 value default

# count_item_strings

# xml_insert_element 28 descr "TCP Offload Engine"
# xml_insert_element 28 tunable net.inet.tcp.tso
# xml_insert_element 28 value default

# count_item_strings

# xml_insert_element 29 descr "UDP Checksums"
# xml_insert_element 29 tunable net.inet.udp.checksum
# xml_insert_element 29 value default

# count_item_strings

# xml_insert_element 30 descr "Maximum socket buffer size"
# xml_insert_element 30 tunable kern.ipc.maxsockbuf
# xml_insert_element 30 value default

# echo "Added Item Elements Successfully!"
# echo

# sleep 1;

# count_group_strings

# xml_group_element 3 name "Role_NOC_Tier_2"
# xml_group_element 3 description "Tier 2 Access"
# xml_group_element 3 member 0
# xml_group_element 3 gid 2012
# xml_group_element 3 priv page-dashboard-all
# xml_group_element 3 priv page-dashboard-widgets
# xml_group_element 3 priv page-diagnostics-system-activity
# xml_group_element 3 priv page-diagnostics-arptable
# xml_group_element 3 priv page-diagnostics-command
# xml_group_element 3 priv page-diagnostics-cpuutilization
# xml_group_element 3 priv page-diagnostics-crash-reporter
# xml_group_element 3 priv page-diagnostics-haltsystem
# xml_group_element 3 priv page-diagnostics-interfacetraffic
# xml_group_element 3 priv page-diagnostics-logs-firewall
# xml_group_element 3 priv page-diagnostics-logs-gateways
# xml_group_element 3 priv page-diagnostics-logs-pptpvpn
# xml_group_element 3 priv page-diagnostics-logs-resolver
# xml_group_element 3 priv page-diagnostics-logs-settings
# xml_group_element 3 priv page-diagnostics-logs-system
# xml_group_element 3 priv page-diagnostics-packetcapture
# xml_group_element 3 priv page-diagnostics-ping
# xml_group_element 3 priv page-diagnostics-rebootsystem
# xml_group_element 3 priv page-diagnostics-routingtables
# xml_group_element 3 priv page-diagnostics-statessummary
# xml_group_element 3 priv page-diagnostics-traceroute
# xml_group_element 3 priv page-firewall-alias-edit
# xml_group_element 3 priv page-firewall-alias-import
# xml_group_element 3 priv page-firewall-aliases
# xml_group_element 3 priv page-firewall-nat-1-1
# xml_group_element 3 priv page-firewall-nat-1-1-edit
# xml_group_element 3 priv page-firewall-nat-outbound
# xml_group_element 3 priv page-firewall-nat-outbound-edit
# xml_group_element 3 priv page-firewall-nat-portforward
# xml_group_element 3 priv page-firewall-nat-portforward-edit
# xml_group_element 3 priv page-firewall-rules
# xml_group_element 3 priv page-firewall-rules-edit
# xml_group_element 3 priv page-firewall-virtualipaddress-edit
# xml_group_element 3 priv page-firewall-virtualipaddresses
# xml_group_element 3 priv page-getstats
# xml_group_element 3 priv page-hidden-detailedstatus
# xml_group_element 3 priv page-hidden-nolongerincluded
# xml_group_element 3 priv page-hidden-uploadconfiguration
# xml_group_element 3 priv page-interfaces
# xml_group_element 3 priv page-interfaces-assignnetworkports
# xml_group_element 3 priv page-interfaces-bridge
# xml_group_element 3 priv page-interfaces-bridge-edit
# xml_group_element 3 priv page-interfaces-groups
# xml_group_element 3 priv page-interfaces-groups
# xml_group_element 3 priv page-interfaces-lagg
# xml_group_element 3 priv page-interfaces-vlan
# xml_group_element 3 priv page-interfaces-vlan-edit
# xml_group_element 3 priv page-ipsecxml
# xml_group_element 3 priv page-loadbalancer-pool
# xml_group_element 3 priv page-loadbalancer-pool-edit
# xml_group_element 3 priv page-loadbalancer-virtualserver-edit
# xml_group_element 3 priv page-openvpn-client
# xml_group_element 3 priv page-openvpn-client-export
# xml_group_element 3 priv page-openvpn-csc
# xml_group_element 3 priv page-openvpn-server
# xml_group_element 3 priv page-package-edit
# xml_group_element 3 priv page-package-settings
# xml_group_element 3 priv page-pkg-mgr-settings
# xml_group_element 3 priv page-requiredforjavascript
# xml_group_element 3 priv page-services-loadbalancer-monitor
# xml_group_element 3 priv page-services-loadbalancer-monitor-edit
# xml_group_element 3 priv page-services-loadbalancer-relay-action
# xml_group_element 3 priv page-services-snmp
# xml_group_element 3 priv page-services-snort
# xml_group_element 3 priv page-status-carp
# xml_group_element 3 priv page-status-cpuload
# xml_group_element 3 priv page-status-gatewaygroups
# xml_group_element 3 priv page-status-gateways
# xml_group_element 3 priv page-status-interfaces
# xml_group_element 3 priv page-status-ipsec
# xml_group_element 3 priv page-status-loadbalancer-pool
# xml_group_element 3 priv page-status-loadbalancer-virtualserver
# xml_group_element 3 priv page-status-openvpn
# xml_group_element 3 priv page-status-packagelogs
# xml_group_element 3 priv page-status-services
# xml_group_element 3 priv page-status-systemlogs-ipsecvpn
# xml_group_element 3 priv page-status-systemlogs-loadbalancer
# xml_group_element 3 priv page-status-systemlogs-openvpn
# xml_group_element 3 priv page-status-systemlogs-ppp
# xml_group_element 3 priv page-status-trafficgraph
# xml_group_element 3 priv page-system-gateways
# xml_group_element 3 priv page-system-gateways-editgateway
# xml_group_element 3 priv page-system-gateways-editgatewaygroups
# xml_group_element 3 priv page-system-gatewaygroups
# xml_group_element 3 priv page-system-generalsetup
# xml_group_element 3 priv page-system-login/logout
# xml_group_element 3 priv page-system-packagemanager
# xml_group_element 3 priv page-system-packagemanager-installed
# xml_group_element 3 priv page-system-packagemanager-installpackage
# xml_group_element 3 priv page-system-staticroutes
# xml_group_element 3 priv page-system-staticroutes-editroute
# xml_group_element 3 priv page-vpn-ipsec
# xml_group_element 3 priv page-vpn-ipsec-editkeys
# xml_group_element 3 priv page-vpn-ipsec-editphase1
# xml_group_element 3 priv page-vpn-ipsec-editphase2
# xml_group_element 3 priv page-vpn-ipsec-listkeys
# xml_group_element 3 priv page-vpn-vpnpptp
# xml_group_element 3 priv page-vpn-vpnpptp-user-edit
# xml_group_element 3 priv page-vpn-vpnpptp-users
# xml_group_element 3 priv page-system-firmware-autoupdate
# xml_group_element 3 priv page-system-firmware-checkforupdate
# xml_group_element 3 priv page-vpn-ipsec-mobile
# xml_group_element 3 priv page-system-usermanager
# xml_group_element 3 priv page-system-usermanager-addprivs

# echo "Added Tier 2 Group Successfully!"
# echo

# sleep 1;

# count_group_strings

# xml_group_element 4 name Role_NOC_Tier_3
# xml_group_element 4 description "Tier 3 Access"
# xml_group_element 4 member 0
# xml_group_element 4 gid 2011
# xml_group_element 4 priv page-all

# echo "Added Tier 3 Group Successfully!"
# echo

sleep 1;

update_users 1 disabled

# count_user_strings

# update_users 2 scope user
# update_users 2 md5-hash '3db3fd05a325d5cd49cc331823cda2bd'
# update_users 2 name backuppc
# update_users 2 descr 
# update_users 2 expires
# update_users 2 authorizedkeys 'c3NoLXJzYSBBQUFBQjNOemFDMXljMkVBQUFBREFRQUJBQUFCQVFDaDd1MHZ3Q2pTM3h4UStWWjhzb3gwaXBNNVAxUmltWUg3TkRiYWRBMlYwNlVHblZvUTFBOG5NYTMrb2NTRTF5US9qNUxoS0U1cUd2MFlHM3RSL0F2K29QdXMvSE85Zkh6T0tzYlhMLzhxckVpY3hvY3ZuNm5nY2lZU25xQ3V0eXVHb3pQWmQ5SmF3bU5pbC9JT2lwMnFEVmxZUGxWaFY1MVR4OWJ6cVVhQk1qNmFNdEFXSHM5WE5Zb3Y3ZDk4UTA0SXJieEFVZTJJZVQ0UHNpdjZva25Nc0NkSGczOEprV0draC9CY3hpWWhMcjlFVlhJSG9iQWVHWGJwbUhxaENnckFFU1YxWTVMT3F4T2FWMGVuRTc5TWRsY0I4dXh0ZmY0ZUp6RzFFSGkycWtwdnFRWE41VW51UHlaN2ZXY1NqVlBDT2FiTklUN29YRGJwK0QrNkJUbXQgYmFja3VwcGNAaGVyYQ=='
# update_users 2 ipsecpsk
# update_users 2 uid 2000
# update_users 2 priv user-copy-files
# update_users 2 priv user-shell-access

# echo "Updating/Adding Users Completed!"
# echo

# sleep 1;

# update_settings

# echo "Updating Settings Completed!"
# echo

# sleep 1;

# add_ssl noantilockout
# add_ssl authmode "dcro01.orl-fl.us"
# add_ssl nodnsrebindcheck
# add_ssl nohttpreferercheck

# add_wildcard_cert

# cert_config 2 refid 591cb9c537fad
# cert_config 2 descr *.anetmgmt.net
# cert_config 2 crt LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tDQpNSUlHVWpDQ0JUcWdBd0lCQWdJUkFPTjNiOWVBaWdYbUVGOCsxZTVudXE4d0RRWUpLb1pJaHZjTkFRRUxCUUF3DQpnWkF4Q3pBSkJnTlZCQVlUQWtkQ01Sc3dHUVlEVlFRSUV4SkhjbVZoZEdWeUlFMWhibU5vWlhOMFpYSXhFREFPDQpCZ05WQkFjVEIxTmhiR1p2Y21ReEdqQVlCZ05WQkFvVEVVTlBUVTlFVHlCRFFTQk1hVzFwZEdWa01UWXdOQVlEDQpWUVFERXkxRFQwMVBSRThnVWxOQklFUnZiV0ZwYmlCV1lXeHBaR0YwYVc5dUlGTmxZM1Z5WlNCVFpYSjJaWElnDQpRMEV3SGhjTk1UY3dOREExTURBd01EQXdXaGNOTVRnd05EQTFNak0xT1RVNVdqQmJNU0V3SHdZRFZRUUxFeGhFDQpiMjFoYVc0Z1EyOXVkSEp2YkNCV1lXeHBaR0YwWldReEhUQWJCZ05WQkFzVEZGQnZjMmwwYVhabFUxTk1JRmRwDQpiR1JqWVhKa01SY3dGUVlEVlFRRERBNHFMbUZ1WlhSdFoyMTBMbTVsZERDQ0FpSXdEUVlKS29aSWh2Y05BUUVCDQpCUUFEZ2dJUEFEQ0NBZ29DZ2dJQkFPdHZPQkhwL1dEaEsxbzdnN2JqZmhid0hMd1pJeThKcklYMUIvTGdON1JJDQphZEJIcWRsUVZxR2lvMkpIL2VKOTljOWhmOTdSZml4eFhja2lDbWFUT2ozcXNTQ2RGZVErSUhtVC94TDBESXQ2DQpPS29DbGtwT3pjek9ZMmJIdGdzRnc1QmExYUp2V29ycHN0NE14MzhGUkxjbVF2Vy9uVmxSa3ZCN3o1NFh0c3gzDQpPbFUybWRhbWQ1WWVLNkY0V1dEam56bHk4UVFyNnFDSWhpak0xV3pySTdSQmR3dmtJbVlyVUd3MVRnVTJGZVp6DQpDRnE1TUJiTXN6VDRBRTRYaTl2MnhxWHNWUGRCdkhyREhROWVHK3NFd2E0OEJxdGs1VmxXV0RqREk5YVpNOEVVDQpmOFZPNWVsTTB3ZUMwK3krdFdtNC9XV1dESktLMk1IYmpTTlhGb1dCM0hXbjllU24xTEhvYTFaUmJvTkdFaVRKDQpFRzA0WlRJeXZHSnc1TXMySGNLZHR3TWxtSUU5cXQ2UWJHK2RSN010YWNOeExJYUE0azI0VHZ4UkVuUExpclpKDQppY2lkYnhYSGJUUFp5TnQwZlZpOWxjRUtiRWRhUGw0UEVjdkFJYnVIeEhTdUlNMml0MTI0V2d1Z1dnWktOdFVxDQpiNG1yaG82YTRLUTQxcU1ITENOSUQ3b1VUUDFEZnBYeDN3dTFNdEF1NnJlM0NwTzNWK1lHeXIrYStHbjVGQklwDQpDWTlHV01uM0lmQ1JDQ3hPYWRscUhicmJNVVhYWjdlSElDNUV6ZEl2bXdOQ0pKQzdlV1A2dXRKamVlUE8xNlgrDQpBUkFYL05tVHpiaHpxSE9MTlhMczZPS0dlMFRkMVgvbGVRNHYrcHVNTkw5aVNCalNrQmZjOG5yMEQwU0RmYWdoDQpBZ01CQUFHamdnSFpNSUlCMVRBZkJnTlZIU01FR0RBV2dCU1FyMm82bEZvTDJKRHFFbFp6MzBPME9pamE1ekFkDQpCZ05WSFE0RUZnUVVUY1Z1elF0T3NWajg2L0hrRmY5QW5iaWFJQTh3RGdZRFZSMFBBUUgvQkFRREFnV2dNQXdHDQpBMVVkRXdFQi93UUNNQUF3SFFZRFZSMGxCQll3RkFZSUt3WUJCUVVIQXdFR0NDc0dBUVVGQndNQ01FOEdBMVVkDQpJQVJJTUVZd09nWUxLd1lCQkFHeU1RRUNBZ2N3S3pBcEJnZ3JCZ0VGQlFjQ0FSWWRhSFIwY0hNNkx5OXpaV04xDQpjbVV1WTI5dGIyUnZMbU52YlM5RFVGTXdDQVlHWjRFTUFRSUJNRlFHQTFVZEh3Uk5NRXN3U2FCSG9FV0dRMmgwDQpkSEE2THk5amNtd3VZMjl0YjJSdlkyRXVZMjl0TDBOUFRVOUVUMUpUUVVSdmJXRnBibFpoYkdsa1lYUnBiMjVUDQpaV04xY21WVFpYSjJaWEpEUVM1amNtd3dnWVVHQ0NzR0FRVUZCd0VCQkhrd2R6QlBCZ2dyQmdFRkJRY3dBb1pEDQphSFIwY0RvdkwyTnlkQzVqYjIxdlpHOWpZUzVqYjIwdlEwOU5UMFJQVWxOQlJHOXRZV2x1Vm1Gc2FXUmhkR2x2DQpibE5sWTNWeVpWTmxjblpsY2tOQkxtTnlkREFrQmdnckJnRUZCUWN3QVlZWWFIUjBjRG92TDI5amMzQXVZMjl0DQpiMlJ2WTJFdVkyOXRNQ2NHQTFVZEVRUWdNQjZDRGlvdVlXNWxkRzFuYlhRdWJtVjBnZ3hoYm1WMGJXZHRkQzV1DQpaWFF3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUg3WjREQXlmN21KamVaZUxYVlhzZHNmQnRQcGordHFXTWRFDQpra2hsajNNbzF3YWdnYnBvdE1YVnJ3eUpuSFRLdU94TzlvK1lLV2F4WWFENXJ5bnRNbGdVVXpyTHNkNDNXRzl3DQo2SEc0cmFSelBRZngvbUIyeXYveFRaSm93K1NucWNhTkkxMmk3T3lvQmNXWHVXeGQrdlpJdnl6bkZZMkt5eGJyDQpTOHJpVVRlVzFidmlhUU9vZDQ3Y09aZ1ViQk9wMDVvM2VWOFMrWGp4bjF5K1hpNHcrblg5R0tlS29iWFg5Q3RhDQp6am00cFRoWGdlc1MrK0dKSTJSUEt5OTlad0lDZVNXZm52VUh4TUc0ejgyNGVNYWtGYWlVZmUvV1loN2FLOFlTDQoyL3ZDTm84VWQ4ajhkakNZM25CNmo1cCtUL0t6ZVhkek14VmZXVkg4K1h2eTRWbE1pQzg9DQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tDQo=
# cert_config 2 prv LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tDQpNSUlKUXdJQkFEQU5CZ2txaGtpRzl3MEJBUUVGQUFTQ0NTMHdnZ2twQWdFQUFvSUNBUURyYnpnUjZmMWc0U3RhDQpPNE8yNDM0VzhCeThHU012Q2F5RjlRZnk0RGUwU0duUVI2blpVRmFob3FOaVIvM2lmZlhQWVgvZTBYNHNjVjNKDQpJZ3Bta3pvOTZyRWduUlhrUGlCNWsvOFM5QXlMZWppcUFwWktUczNNem1ObXg3WUxCY09RV3RXaWIxcUs2YkxlDQpETWQvQlVTM0prTDF2NTFaVVpMd2U4K2VGN2JNZHpwVk5wbldwbmVXSGl1aGVGbGc0NTg1Y3ZFRUsrcWdpSVlvDQp6TlZzNnlPMFFYY0w1Q0ptSzFCc05VNEZOaFhtY3doYXVUQVd6TE0wK0FCT0Y0dmI5c2FsN0ZUM1FieDZ3eDBQDQpYaHZyQk1HdVBBYXJaT1ZaVmxnNHd5UFdtVFBCRkgvRlR1WHBUTk1IZ3RQc3ZyVnB1UDFsbGd5U2l0akIyNDBqDQpWeGFGZ2R4MXAvWGtwOVN4Nkd0V1VXNkRSaElreVJCdE9HVXlNcnhpY09UTE5oM0NuYmNESlppQlBhcmVrR3h2DQpuVWV6TFduRGNTeUdnT0pOdUU3OFVSSnp5NHEyU1luSW5XOFZ4MjB6MmNqYmRIMVl2WlhCQ214SFdqNWVEeEhMDQp3Q0c3aDhSMHJpRE5vcmRkdUZvTG9Gb0dTamJWS20rSnE0YU9tdUNrT05hakJ5d2pTQSs2RkV6OVEzNlY4ZDhMDQp0VExRTHVxM3R3cVR0MWZtQnNxL212aHArUlFTS1FtUFJsako5eUh3a1Fnc1RtblphaDI2MnpGRjEyZTNoeUF1DQpSTTNTTDVzRFFpU1F1M2xqK3JyU1kzbmp6dGVsL2dFUUYvelprODI0YzZoeml6Vnk3T2ppaG50RTNkVi81WGtPDQpML3FiakRTL1lrZ1kwcEFYM1BKNjlBOUVnMzJvSVFJREFRQUJBb0lDQUh1SzB5dGpVOWlBajlVN29iUlkwQk9ODQpVQ2JNTWhBK3pVOUY4elBad0tGVDFtSzdHRCsyenA3bXowR0ZjWTVtZHBTcUh3VjNmUFFwVVFONFgyalFIU0hjDQpnN0lQZkN0WEJvZUZ4N1hVWnJqU0crWHFrWjdRbDJHL2M1MjljcU42Rk5NdE55bVRzVGx2eExLTWxpcnJRdEd3DQp2RFprcEZiNFhWamdQMlJBSVdaTnNraUE3RjBjNFdmZTBScGNJdHFhMXpTNFFnemtWcXlDdDVPMVdORmMybEYrDQpnTSsybU81d0VEV1lDeWJrNkwwUzQvRm5kL3FlMC9NWnFGOVNMOHZ2UlBKUWY0MTM2MFdvR1JtMVVvVVM2K2RZDQpERS9vRkFtN0szUXR3aUtjSmZKTnBYYU9Ia3M4U3dpSCtGa2xBZUZHZDRIVktTZkV3RldKdGhnelhOZ1YrdTZvDQoycldvaUFiQ09RdWZzQkNYK0hHNTFNMWJYemxHYXFibFN3V1l1N2xiNW1FbmdCVlhBZlJ5anlKZXBzR1h4RE5wDQpmaUxaRVFlTGFIVkJPK1NkYjEveWRob0xLMi9lVitTd1RtZktyT0l4QjcxSndoaGpnSzNxMHoyaWtreTQxSjNzDQpZUExjZDVwb2g0dWZxeVBaUStmbnNOSFI5cG5VZGQ5M3lyUXhNS1pwNDZFdldwTW1sSFNlZk5GYjBBZm9JYWZmDQp0Tk5PV3dLV3NURzNQT0dac2w2ays2bjkzZktubTFiMzJ0NEtPdDF4a205RkE0d2hwcWZJWlRMQzhTc0lGMXU3DQprM3hWQmZCQkxPZUQrclVEenAyT2Z0V3RrdXFWYkxsb3RvbzBrOEVBYjIyZlg0enFUbEEwTERTTzZURkYzOUlPDQo4VXFOR3piN0VFVGl4NDhWMzJnaEFvSUJBUUQyT3VUZUorOWtuRVI1OS9XQjE1eXpNMDZBS2RNdldjRGV6NEdIDQplVm1QbkZRdTVkVlZEdkdZeEhZNFR2bTJsc1JOS2ljRHJGakxhRDQraUFDWllMVm4vWHE4N09UVTZwVDVjNElhDQpzdG9VOHYzMzVsb0VPSDIwNUpNd0kya2VVRDhERjlya1pwWlcvd3RJTitJLzJ6RlE2Qm1tMytsV1llcDJUcVc2DQpxYXorNDc0cFBEVERDS0NtaUIzNUQxaDA0aG9vTFBGZTJSMXhKTjh6RzlFMGFKUHd0OTdwcFdvN245eDBBTlVZDQpwZWozd2pJblNKak9ycWpmcDFGMW9NZWVlMzUrdmhtUy9rVEJjalV3dFF1bXFwR05aRWhKMDJsNUFSTTV4V0VSDQpPWk4xR1hRd0RJU2Z6ZkliOUdRVUpIM1c2aHNOR0lJOG5HSXZQZlNHYmRJUUY2QjFBb0lCQVFEMHhxcm0yNWFJDQpvbEUra0s0aUEvKzVSV01WazE2ZEtoczRwcmo0NFF4NEdCMW5jMmZyOHdLSlR4MkxVSmVIeUlHMkRLeEpuK1ZDDQppWkZ3dXAwcm5RaDVwTjJnWTd6SENmWE9Yc21OemdnYkdIcThMVlBFejlaS3A1am5pU0RpeUJWUzUvWkM1N0ZGDQpReGNLSFVMWFA4YVo5M0dxTjhMTUxBbTJFWkh0VXZVTnRXaGEvdVllMC9BQWhEUlFnS09oWGc3VXdvdVdoRG04DQpaeld5TlVzalBTOVpFZ3pWMUk0M1hLRi9EWVVkMlRPcHVpUXEramhzQlRMdHRPVzl0bmtaN1M3MDNUcGxianY2DQpxN2Y1cjcyWHc4Z0tnZHlTTkFsNmxGRldEam5OYXJQanAvWmRINTVxOEFibDJOMm9ZYVU5czk4RUNUWHFLUmo2DQowT01nMllRM2FUTjlBb0lCQVFDdGV5VVJHSlhrRHUxMythbXh4NVdSOUU0VW9tTTJjMGdlTTVrUk9BQlAzRmE3DQpqQmJZRE9WUE91d0lGQ3gvNW8xN3lIMGdhMmRNT0svU0lzUTVUQmZEb3FXOVFqS2ZpSDlabVhaTEZVUHRpcDVBDQo4THp2U0ZYWkEwcG9taXBQdno0R0VlS1pGV1pLK1BxYjhUT294ZWhqRm9Rc1BJb0w0SVR1d2M2bVN6R2xqQlBJDQp2YkIyMFRkTzNZd3dsQTFBbktUTk5ZMEJ4SHFuNHRDWEU3dzc3b3A5Q1M4Mjh1SjhDOCtvczRWd0RrU3JldGtYDQpNR0RwRGNuUmVmTThxd0M1dWt5UFE2U0ZHanliQnJwUEROK2VsNEpoV2d4TVozVmlXYzJQNEc3WlVmV0FoV1NGDQpEZXpMSXJDMzNXSTlodEJhZ1NwNStaQ1kzNTJWcDFNRys0MEs1WHFaQW9JQkFRQ0ZrM1RvRHFVVFl5RGE5N0ZQDQpOc2R5bjM3MjR6a2FvME8vb3B3R2xTbHMwQndidkVyVjVBTmFVeVpZUkY2czVxcUNZbUFTdllNcTBFL2lLTFJrDQpmSW1IZUlUSlppUTZxaUROd2NSVDhqOVNLZ1d3Y3p2bmgxUDE0WWY3c2tXVC9JUkdmZmRSZzRhbHVYcjFOZ3FuDQoxRkhZNjhQSGxDNWxwUktYblBiNWYrL2l6MEJuaC9xa2tCdkU3R0J3SGdNdHFGcUhtTEw4TEtRbFFGMTVKc1FlDQpNdUdIeGVYak90OXhMc2Vpd2dvR3crVUJsbWJ1WFNZMUxKRWlUem1nVWRlOFlrYmhzV2lRdVp0WnJDUDF5Z1c0DQpzRXFXRVZBQktReVRMQ1ZHeFBTZU9NQjZWOHFGL3g5QVZFUXZZaTEwR2ZWR3VzWFZPZ0dHQzI5cVVGdmlMVkdODQp1NGN4QW9JQkFHbHc0R3k1cVJCRGNkYVRaSVRHNW5aYVNKaWo0REhTa3VJSmp2TkIzR3hwR29iRGFha05udTh0DQprMDdlUU1qMitVUnZ6dHNXVWVaQnc1WkpDR0Znc0ZvY3JZUlo5U1N2eW92WGxoZE0wNXIvSXBiTWZBYXFrMTBqDQpBbmx5d3NFR2NKdDJwaUIrckJlY2EyTE8zLzBQUzdhc3BVT2s1cFpGdHNySzRLZFZtN0xER28vTWVqblJWNUtBDQpINUJCb29Kd0tjaHE3SVZTK1ZKdHY3TnhmcmlQK214U0tYSllWOGR6cFFYcEF4Q1VUMzVrM2o0NXk3c3V0ay9vDQo2YTRzT1hNTkhITFFiYms4emJIMzBnTjJpTXFLb25idldyS2YxS2ptbG80elc5RTR4bHVjUG5jOGcraXFMdUhyDQo2VmRIemY4RDdBZmNEbjVzQ0xCU045N2Vqbi96Mi9ZPQ0KLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLQ==

# sleep 1;

# echo "Adding SSL Completed!"
# echo

# sleep 1;

# more_settings authserver ""
# more_settings enablebinatreflection yes
# more_settings natreflectionhelper yes
# more_settings enablenatreflectionpurenat yes

# echo "More System Settings Completed!"
# echo

# sleep 1;

# echo "Editing AuthServer"

# authserver_settings refid "52ead338acf38"
# authserver_settings type ldap
# authserver_settings name dcro01.orl-fl.us
# authserver_settings host "dcro01.orl-fl.us.atlantic.net"
# authserver_settings ldap_port 389
# authserver_settings ldap_urltype "TCP - Standard"
# authserver_settings ldap_protver 3
# authserver_settings ldap_scope subtree
# authserver_settings ldap_basedn "DC=anet,DC=local"
# authserver_settings ldap_authcn "OU=NOC,OU=Anet Users,DC=anet,DC=local"
# authserver_settings ldap_extended_enabled
# authserver_settings ldap_extended_query
# authserver_settings ldap_attr_user "samAccountName"
# authserver_settings ldap_attr_group "cn"
# authserver_settings ldap_attr_member "memberOf"
# authserver_settings ldap_binddn "pfsense"
# authserver_settings ldap_bindpw "qTh6MGqz1!"

# echo "Done Editing AuthServer!"
# echo

# sleep 1;

echo "Setting Up Interfaces..."

wan_settings

echo "WAN Interface Setup!"
echo

sleep 1;

lan_settings

echo "LAN Interface Setup!"
echo

# backup_settings
# # backup_settings enable
# # backup_settings ipaddr "$BAKINTIP"
# # backup_settings subnet "$BAKINTCIDR"

# echo "BACKUP Interface Setup!"
# echo

echo "Setting Up WAN Gateway..."

# wan_gateway

# wan_gateway_settings interface wan
wan_gateway_settings
# wan_gateway_settings name "GW_WAN"
# wan_gateway_settings weight 1
# wan_gateway_settings ipprotocol inet
# wan_gateway_settings interval
# wan_gateway_settings descr "Interface Wan Gateway"
# wan_gateway_settings defaultgw

# sleep 1;

echo "Additional Settings being Updated..."

dhcp_removal

sleep 1;

# dnsmasq_enable enable

# sleep 1;

# echo "SNMP Settings...."

# snmpd_settings modules

# snmpd_modules mibii
# snmpd_modules netgraph
# snmpd_modules pf
# snmpd_modules hostres
# snmpd_modules ucd
# snmpd_modules regex

# snmpd_settings pollport 161
# snmpd_settings trapserver
# snmpd_settings trapserverport 162
# snmpd_settings trapstring
# snmpd_settings bindip
# snmpd_settings enable

# echo "SNMP Settings done!"
# echo

# sleep 1;

diag_setting

sleep 1;

# echo "Adding Firewall Rules..."

# count_rule_strings

# adding_rules 4 id
# adding_rules 4 type pass
# adding_rules 4 interface wan
# adding_rules 4 ipprotocol inet
# adding_rules 4 tag
# adding_rules 4 tagged
# adding_rules 4 direction any
# adding_rules 4 floating yes
# adding_rules 4 max
# adding_rules 4 max-src-nodes
# adding_rules 4 max-src-conn
# adding_rules 4 max-src-states
# adding_rules 4 statetimeout
# adding_rules 4 statetype "keep state"
# adding_rules 4 os
# adding_rules 4 protocol icmp
# adding_rules 4 source

# editing_source_address 1 address MONITORING 4

# adding_rules 4 destination

# editing_destination_address 1 any "" 4

# adding_rules 4 descr "Allow Ping Monitoring For WAN &amp; LAN"
# adding_rules 4 updated

# editing_updated 1 time "1391107663" 4
# editing_updated 1 username "admin@209.208.0.193" 4

# adding_rules 4 created

# editing_created 1 time "1391107663" 4
# editing_created 1 username admin@209.208.0.193 4

# adding_rules 4 tracker "1449670172"

# echo "PING MONITORING rule added"
# echo

# sleep 1;

# count_rule_strings

# adding_rules 5 id
# adding_rules 5 type pass
# adding_rules 5 interface wan
# adding_rules 5 ipprotocol inet
# adding_rules 5 tag
# adding_rules 5 tagged
# adding_rules 5 direction any
# adding_rules 5 floating yes
# adding_rules 5 max
# adding_rules 5 max-src-nodes
# adding_rules 5 max-src-conn
# adding_rules 5 max-src-states
# adding_rules 5 statetimeout
# adding_rules 5 statetype "keep state"
# adding_rules 5 os
# adding_rules 5 protocol udp
# adding_rules 5 source

# editing_source_address 1 address MONITORING 5

# adding_rules 5 destination

# editing_destination_address 1 any "" 5
# editing_destination_address 1 port 161 5

# adding_rules 5 descr "Allow SNMP Monitoring For WAN &amp; LAN"
# adding_rules 5 updated

# editing_updated 1 time "1391107714" 5
# editing_updated 1 username "admin@209.208.0.193" 5

# adding_rules 5 created

# editing_created 1 time "1391107714" 5
# editing_created 1 username admin@209.208.0.193 5

# adding_rules 5 tracker "1449670173"

# echo "SNMP MONITORING rule added"
# echo

# sleep 1;

# count_rule_strings

# adding_rules 6 id
# adding_rules 6 type block
# adding_rules 6 interface lan
# adding_rules 6 ipprotocol inet
# adding_rules 6 tag
# adding_rules 6 tagged
# adding_rules 6 max
# adding_rules 6 max-src-nodes
# adding_rules 6 max-src-conn
# adding_rules 6 max-src-states
# adding_rules 6 statetimeout
# adding_rules 6 statetype "keep state"
# adding_rules 6 os
# adding_rules 6 source

# editing_source_address 1 network lan 6

# adding_rules 6 destination

# editing_destination_address 1 network wan 6

# adding_rules 6 descr "Block Traffic To FW WAN From Customer "
# adding_rules 6 updated

# editing_updated 1 time "1391108079" 6
# editing_updated 1 username "admin@209.208.0.193" 6

# adding_rules 6 created

# editing_created 1 time "1391108043" 6
# editing_created 1 username admin@209.208.0.193 6

# adding_rules 6 tracker "1449670174"

# count_rule_strings

# adding_rules 7 id
# adding_rules 7 type block
# adding_rules 7 interface lan
# adding_rules 7 ipprotocol inet
# adding_rules 7 tag
# adding_rules 7 tagged
# adding_rules 7 max
# adding_rules 7 max-src-nodes
# adding_rules 7 max-src-conn
# adding_rules 7 max-src-states
# adding_rules 7 statetimeout
# adding_rules 7 statetype "keep state"
# adding_rules 7 os
# adding_rules 7 source

# editing_source_address 1 network lan 7

# adding_rules 7 destination

# editing_destination_address 1 network lanip 7

# adding_rules 7 descr "Block Traffic To FW LAN From Customer"
# adding_rules 7 updated

# editing_updated 1 time "1391108023" 7
# editing_updated 1 username "admin@209.208.0.193" 7

# adding_rules 7 created

# editing_created 1 time "1391107981" 7
# editing_created 1 username admin@209.208.0.193 7

# adding_rules 7 tracker "1449670175"

# update_rules 1 "1449670176" 1
# update_rules 1 "1449670177" 2

# echo "All FW rules added"
# echo

# sleep 1;

# count_rule_strings

# adding_rules 8 id
# adding_rules 8 type pass
# adding_rules 8 interface opt1
# adding_rules 8 ipprotocol inet
# adding_rules 8 tag
# adding_rules 8 tagged
# adding_rules 8 max
# adding_rules 8 max-src-nodes
# adding_rules 8 max-src-conn
# adding_rules 8 max-src-states
# adding_rules 8 statetimeout
# adding_rules 8 statetype "keep state"
# adding_rules 8 os
# adding_rules 8 source

# editing_source_address 1 address "BACKUP_PC" 8

# adding_rules 8 destination

# editing_destination_address 1 any "" 8

# adding_rules 8 descr "Allow Backup Traffic From Hera"
# adding_rules 8 updated

# editing_updated 1 time "1391107909" 8
# editing_updated 1 username "admin@209.208.0.193" 8

# adding_rules 8 created

# editing_created 1 time "1391107909" 8
# editing_created 1 username admin@209.208.0.193 8

# adding_rules 8 tracker "1449670178"

# count_rule_strings

# echo "Backup rules added"
# echo

# sleep 1;

# adding_rules 9 id
# adding_rules 9 type pass
# adding_rules 9 interface enc0
# adding_rules 9 ipprotocol inet
# adding_rules 9 tag
# adding_rules 9 tagged
# adding_rules 9 max
# adding_rules 9 max-src-nodes
# adding_rules 9 max-src-conn
# adding_rules 9 max-src-states
# adding_rules 9 statetimeout
# adding_rules 9 statetype "keep state"
# adding_rules 9 source

# editing_source_address 1 address "VPN_RANGE" 9

# adding_rules 9 destination

# editing_destination_address 1 any "" 9

# adding_rules 9 descr

# echo "VPN_RANGE rules added"
# echo

# sleep 1;

echo "Configuring IPSec..."

configuring_ipsec_nodes

configuring_ipsec_client 1 enable
configuring_ipsec_client 1 user_source "Local Database"
configuring_ipsec_client 1 group_source none
configuring_ipsec_client 1 pool_address "$VPNIP"
configuring_ipsec_client 1 pool_netbits "$VPNIPNET"
configuring_ipsec_client 1 dns_server1 "209.208.127.65"
configuring_ipsec_client 1 dns_server2 "209.208.25.18"
configuring_ipsec_client 1 dns_server3
configuring_ipsec_client 1 dns_server4

echo "IPSec Client Side Done"
echo

sleep 1;

configuring_ipsec_phase1 1 ikeid 1
configuring_ipsec_phase1 1 iketype auto
configuring_ipsec_phase1 1 mode main
configuring_ipsec_phase1 1 interface wan
configuring_ipsec_phase1 1 mobile
configuring_ipsec_phase1 1 protocol inet
configuring_ipsec_phase1 1 myid_type myaddress
configuring_ipsec_phase1 1 myid_data
configuring_ipsec_phase1 1 peerid_type fqdn
configuring_ipsec_phase1 1 peerid_data "$FQDN"
configuring_ipsec_phase1 1 encryption-algorithm

editing_phase1_encryption 1 name aes
editing_phase1_encryption 1 keylen 256

configuring_ipsec_phase1 1 hash-algorithm sha1
configuring_ipsec_phase1 1 dhgroup 14
configuring_ipsec_phase1 1 lifetime 86400
configuring_ipsec_phase1 1 pre-shared-key presk
configuring_ipsec_phase1 1 private-key
configuring_ipsec_phase1 1 certref
configuring_ipsec_phase1 1 caref
configuring_ipsec_phase1 1 authentication_method xauth_psk_server
configuring_ipsec_phase1 1 descr
configuring_ipsec_phase1 1 nat_traversal force
configuring_ipsec_phase1 1 mobike off
configuring_ipsec_phase1 1 dpd_delay 10
configuring_ipsec_phase1 1 dpd_maxfail 5

echo "IPSec Phase 1 Complete"

configuring_ipsec_phase2 1 ikeid 1
configuring_ipsec_phase2 1 uniqid "5668372b74125"
configuring_ipsec_phase2 1 mode tunnel
configuring_ipsec_phase2 1 reqid 1
configuring_ipsec_phase2 1 localid 

editing_phase2_localid 1 type lan

configuring_ipsec_phase2 1 remoteid

editing_phase2_remoteid 1 type mobile

configuring_ipsec_phase2 1 protocol esp
configuring_ipsec_phase2 1 encryption-algorithm-option

editing_encryption_algorithm 1 name aes
editing_encryption_algorithm 1 keylen auto

configuring_ipsec_phase2 1 hash-algorithm-option hmac_sha1
configuring_ipsec_phase2 1 pfsgroup 0
configuring_ipsec_phase2 1 lifetime 3600
configuring_ipsec_phase2 1 pinghost
configuring_ipsec_phase2 1 descr
configuring_ipsec_phase2 1 mobile

echo "IPSec Setup Complete!"
echo 

sleep 1;

echo "Adding Aliases..."

# count_alias_strings

# adding_aliases 2 name BACKUP_PC
# adding_aliases 2 address 172.16.254.220
# adding_aliases 2 descr "Hera"
# adding_aliases 2 type host
# adding_aliases 2 detail "Entry added Thu, 30 Jan 2014 13:44:49 -0500"

# count_alias_strings

# adding_aliases 3 name LOCAL_LAN
adding_aliases 3 address "$LANRANGE"
# adding_aliases 3 descr "Local"
# adding_aliases 3 type network
# adding_aliases 3 detail "Entry added Thu, 20 Oct 2016 13:44:03 -0500"

# count_alias_strings

# adding_aliases 4 name MONITORING
# adding_aliases 4 address "209.208.50.9 209.208.50.11"
# adding_aliases 4 descr "Ubersmith"
# adding_aliases 4 type host
# adding_aliases 4 detail "Entry added Thu, 30 Jan 2014 13:44:03 -0500||Entry added Thu, 30 Jan 2014 13:44:03 -0500"

# count_alias_strings

# adding_aliases 5 name VPN_RANGE
adding_aliases 5 address "$VPNRANGE"
# adding_aliases 5 descr "IPSec Mobile VPN"
# adding_aliases 5 type network
# adding_aliases 5 detail "Entry added Wed, 09 Dec 2015 09:14:30 -0500"

echo "Added Aliases Successfully!"
echo

echo "Adding Outbound NAT Rules...."

count_nat_rule_strings

outbound_nat 1 source

editing_nat_source 1 network VPN_RANGE 1

outbound_nat 1 sourceport
outbound_nat 1 descr
outbound_nat 1 target
outbound_nat 1 targetip
outbound_nat 1 targetip_subnet
outbound_nat 1 interface lan
outbound_nat 1 poolopts
outbound_nat 1 nonat
outbound_nat 1 destination

editing_nat_destination 1 address LOCAL_LAN 1

outbound_nat 1 updated

editing_nat_updated 1 time "1449670550" 1
editing_nat_updated 1 username "dfoster@209.208.0.193" 1

outbound_nat 1 created

editing_nat_created 1 time "1449670550" 1
editing_nat_created 1 username "dfoster@209.208.0.193" 1

count_nat_rule_strings

outbound_nat 2 source

editing_nat_source 1 network VPN_RANGE 2

outbound_nat 2 sourceport
outbound_nat 2 descr
outbound_nat 2 target
outbound_nat 2 targetip
outbound_nat 2 targetip_subnet 0
outbound_nat 2 interface lan
outbound_nat 2 poolopts
outbound_nat 2 destination

editing_nat_destination 1 any "" 2

outbound_nat 2 updated

editing_nat_updated 1 time "1449670556" 2
editing_nat_updated 1 username "dfoster@209.208.0.193" 2

outbound_nat 2 created

editing_nat_created 1 time "1449670556" 2
editing_nat_created 1 username "dfoster@209.208.0.193" 2

count_nat_rule_strings

echo "Outbound NAT Rules Completed"
echo

sleep 1;

# echo "Adding Cronjobs..."

# count_cron_item_strings

# edit_cron_item_strings 8 minute "*/59"
# edit_cron_item_strings 8 hour "*"
# edit_cron_item_strings 8 mday "*"
# edit_cron_item_strings 8 month "*"
# edit_cron_item_strings 8 wday "*"
# edit_cron_item_strings 8 who root
# edit_cron_item_strings 8 command "/root/check-gmirror.py"

# echo "Done Adding Cronjobs"
# echo

# sleep 1;

echo "Setting up Dashboard Widgets!...."

# edit_widgets

sleep 1;

# echo "Setting Up Notifications...."

# add_notifications

# edit_growl_notifications ipaddress
# edit_growl_notifications password
# edit_growl_notifications name "PHP-Growl"
# edit_growl_notifications notification_name "pfSense growl alert"

# edit_smtp_notifications ipaddress "209.208.60.196"
# edit_smtp_notifications port 25
# edit_smtp_notifications notifyemailaddress "device-alerts@atlantic.net"
# edit_smtp_notifications username "pfsense-alerts@atlantic.net"
# edit_smtp_notifications password "VIijkagd"
# edit_smtp_notifications fromaddress "pfsense-alerts@atlantic.net"
# edit_smtp_notifications authentication_mechanism PLAIN

# echo "Done Adding Notifications."
# echo

echo "Adding snmpd.conf file..."

################################################
# Configure hostname and SNMP community string #
################################################

cat << EOS >> "/usr/local/share/snmp/snmpd.conf"
########################################
# First, map the community name to a "security name"
#
#        sec.name        source    community
com2sec  notConfigUser   default   ${id}

########################################
# Second, map the security name into a group name:
#
#       groupName   securityModel   securityName
group   ROGrp       v1              notConfigUser
group   ROGrp       v2c             notConfigUser

########################################
# Third, create a view for us to let the group have rights to:
#
#      name   incl/excl   subtree   mask(optional)
view   all    included    .1

########################################
# Finally, grant the group read-only access to the view.
#
#        group   context   sec.mod   sec.lev   prefix   read   write   notif
access   ROGrp   ""        any       noauth    exact    all    none    none

########################################
# Define system-level attributes

syslocation   Orlando Data Center
syscontact    Atlantic.Net NOC <noc@atlantic.net>

########################################
# Set up additional tests which may or may not be used
#
# "exec" directives for older net-snmp versions
#
#exec  .1.3.6.1.4.1.5671.1    mdstat  /etc/snmp/check-mdstat
#exec  .1.3.6.1.4.1.5671.2    smart   /etc/snmp/check-smart
#exec  .1.3.6.1.4.1.5671.3.1  3ware1  /etc/snmp/check-3ware /c0/u0
#exec  .1.3.6.1.4.1.5671.3.2  3ware2  /etc/snmp/check-3ware /c1/u0
#exec  .1.3.6.1.4.1.5671.101  qstat   /etc/snmp/qstat
#exec  .1.3.6.1.4.1.5671.102  qwait   /etc/snmp/qwait
#
# "extend" directives for net-snmp 5.2 and newer
#
# Note: the names after "extend" become part of the OID used to query
# that item. Do not change them unless you understand what you're doing.
#
extend gmirror  /root/check-gmirror.sh
extend barnyard /root/check-barnyard.sh

EOS

echo "Finished adding snmpd.conf file"
echo

# echo "Adding Gmirror Script"
# echo

# cat << EOS >> "/root/check-gmirror.sh"
# #!/bin/sh

# stat=$(/sbin/gmirror status | sed -n 2p | awk '{print $2}')

# if [ $stat == DEGRADED ] || [ $stat == REBUILDING ]
 # then
  # echo "WARNING: GMIRROR failure on `hostname`"
 # else
  # echo "GMIRROR Status: GOOD"
  # /sbin/gmirror status
# fi

# EOS

# chmod +x /root/check-gmirror.sh

case "$idsinstall" in
        [yY][eE][sS]|[yY])
			rm /tmp/config.cache
			installing_snort
            ;;
        *)
            continue
esac

echo "Updating Hostname..."
edit_hostname
echo "Hostname Updated."
echo

echo "$PSK" | sed -i '' "s/presk/${PSK}/" ${FILE}

read -p "Enter a new production root password: " pass

redo() {

echo "Password cannot be blank, try again"
read -p "Enter a new production root password: " pass
echo

if [ -z $pass ]; then
 redo
else
 setpw
fi

}

setpw() {

echo "$pass" | pw usermod admin -h 0
echo "$pass" | pw usermod root -h 0
echo "Admin/root password changed to $pass"
rootpass=$(/bin/cat /etc/master.passwd | grep '^root' | awk -F':' '{print $2}')

}

if [ -z $pass ]; then
 redo
else
 setpw
fi

update_password 1

rm /tmp/config*
rm /conf/trigger_initial_wizard

echo "Firewall Script Complete!"

case "$idsinstall" in
        [yY][eE][sS]|[yY])
			update_snort_rules
            ;;
        *)
            continue
esac

shutdown -r now