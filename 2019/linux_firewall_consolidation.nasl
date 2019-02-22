###############################################################################
# OpenVAS Vulnerability Test
# $Id: linux_firewall_consolidation.nasl 1.0 2019-01-18 16:20:00Z $
#
# Gather Linux firewall configuration
#
# Authors:
# Daniel Craig <daniel.craig@xqcyber.com>
#
# Copyright:
# Copyright (c) 2017 XQ Digital Resilience Limited
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.300028");
  script_version("$Revision: 1.0 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-18 16:20:00 +0000 (Thu, 18 Jan 2019) $");
  script_name('Linux Firewall Consolidation');
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 XQ Cyber");
  script_family("Compliance");
  script_dependencies("gather-package-list.nasl", "global_settings.nasl");
  script_mandatory_keys("login/SSH/success");

  exit(0);
}

include("misc_func.inc");
include("ssh_func.inc");

if( get_kb_item( "global_settings/authenticated_scans_disabled" ) ) exit( 0 );

# Check if port for us is known
port = get_preference( "auth_port_ssh" );
if( ! port )
  port = get_kb_item( "Services/ssh" );
if( ! port )
  port = 22;

sock_g = ssh_login_or_reuse_connection();
if (! sock_g)
  exit(1);

host_ip = get_host_ip();
password = kb_ssh_password();

cmd = string('n=/dev/null;e=echo;g=grep;l=lsmod;t=iptables;{ echo "'+ password +'"|sudo -S su; echo "Testing Firewalls";([ -n "$($l|$g \'^ip_tables\')" ] || [ -f /proc/net/ip_tables_names ]) && sudo -n $t -t filter -L INPUT >$n && IPT=1 && $e "$t";([ -n "$($l|$g \'^ip6_tables\')" ] || [ -f /proc/net/ip6_tables_names ]) && sudo -n $t -t filter -L INPUT >$n && IPT=1 && $e "ip6tables";[ "$IPT" ] && $e "$t input policy $(sudo -n $t -t filter -L INPUT|$g policy|$g -oE \'(DROP|ACCEPT)\' || $e unknown)";[ "$IPT" ] && $e "$t input $(sudo -n $t -t filter -L INPUT|$g -vE \'^(Chain|target|$)\'|wc -l) rules";([ "$IPT" ] && [ -n "$($t -L|$g \'^LOG\')" ]) && $e "$t logging enabled";([ -e /dev/pf ] && [ -n "$(pfctl -sa|$g \'Enabled\')" ] && [ -n "$(kldstat|$g \'pf.ko\')" ]) && $e "Packet Filter";[ -s /etc/csf/csf.conf ] && $e "ConfigServer Security & Firewall";(hash ipf 2>$n && [ -n "$(ipf -n -V|$g \'^Running\')" ]) && $e "IP Filter";(hash sysctl 2>$n && [ -n "$(sysctl net.inet.ip.fw.enable 2>$n|$g \'1$\')" ]) && $e "IPFW";SFFW=/usr/libexec/ApplicationFirewall/socketfilterfw;([ -e $SFFW ] && [ -n "$($SFFW --getglobalstate|$g \'Firewall is enabled\')" ]) && $e "Application Firewall";p=$(ps axo args 2>$n);for i in "Little Snitch Daemon" HandsOffDaemon LuLu "Radio Silence";do [ -n "$(echo "$p"|grep "$i"|grep -v grep)" ] && echo $i;done;[ -n "$($l|$g \'^nf*_tables\')" ] && $e "$(nft --version)";([ -s /etc/apf/conf.apf ] && [ $($t -L -n|grep -iom1 sanity|wc -l) -eq 1 ]) && ($e -n "Advanced Policy Firewall " && $g -P \'^DEVEL_MODE(\\s|=)\\s*1\' /etc/apf/conf.apf && $e "in testing mode"); } 2>$n');


buf = ssh_cmd_exec(cmd: cmd);
ssh_close_connection();
log_message(port:port, data:buf);
exit(0);
