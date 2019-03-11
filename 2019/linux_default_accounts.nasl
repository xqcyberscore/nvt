###############################################################################
# OpenVAS Vulnerability Test
# $Id: linux_default_accounts.nasl 1.0 2019-01-28 16:20:00Z $
#
# Check linux hosts for enabled default user accounts
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
  script_oid("1.3.6.1.4.1.25623.1.1.300030");
  script_version("$Revision: 1.0 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-28 16:20:00 +0000 (Mon, 28 Jan 2019) $");
  script_name('Linux Default User Accounts');
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 XQ Cyber");
  script_family("Compliance");
  script_dependencies("gather-package-list.nasl", "ssh_authorization.nasl", "global_settings.nasl");
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

users = '_apt
abrt
adm
backup
bin
chrony
daemon
dbus
dnsmasq
ftp
games
gluster
gnats
gnatst
gopher
halt
irc
landscape
list
ip
lxd
mail
man
messagebus
news
nobody
operator
polkitd
pollinate
proxy
postfix
pulse
qemu
rpc
rpcuser
rtkit
saslauth
shutdown
sshd
sync
sys
syslog
systemd\\-bus\\-proxy
systemd\\-coredump
systemd\\-network
systemd\\-resolve
systemd\\-timesync
tss
unbound
uucp
uuidd
vcsa
www\\-data';

user_re = str_replace(find:'
', replace:'|', string:users);

# unixoid
cmd = string('echo "'+ password +'"|sudo -S 2>/dev/null grep -oE \'^('+ user_re +'):[^\\*]*?:\' /etc/shadow|sed -re \'s/^([^:]+):.*/\\1/\'');

# switch for mac
if(get_kb_item("ssh/login/osx_name")){
	cmd = string('dscacheutil -q user|grep -E \'^(name|shell|password)\'|sed \'N;N;s/\\n/ /g\'|grep -vE \'password: \\* shell: /usr/bin/false\'|grep -vE \'^name: (_uucp|root|_mbsetupuser)\'|grep -E \'^name: (_[[:alpha:]]+|daemon|nobody)\'|sed -E \'s/^name: ([[:graph:]]+) .*/\\1/\'');
}

buf = ssh_cmd_exec(cmd: cmd);
ssh_close_connection();
log_message(port:port, data:"The following default accounts were accessible:\n"+buf);
exit(0);
