###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ssh_root_avamar.nasl 8628 2018-02-01 15:23:45Z cfischer $
#
# Default Password `avam@r` for root Account.
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.140133");
 script_version("$Revision: 8628 $");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Default Password `avam@r` for root Account.");
 script_tag(name:"last_modification", value:"$Date: 2018-02-01 16:23:45 +0100 (Thu, 01 Feb 2018) $");
 script_tag(name:"creation_date", value:"2017-01-31 11:12:08 +0100 (Tue, 31 Jan 2017)");
 script_category(ACT_ATTACK);
 script_family("Default Accounts");
 script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
 script_require_ports("Services/ssh", 22);

 script_tag(name: "summary" , value: 'The remote host has the password `avam@r` for the root account.');

 script_tag(name: "impact" , value:'This issue may be exploited by a remote attacker to gain access to sensitive information or modify system configuration.');

 script_tag(name: "vuldetect" , value: 'Try to login with default credentials.');
 script_tag(name: "insight" , value: 'It was possible to login with default credentials: root/avam@r');
 script_tag(name: "solution" , value: 'Change the password.');
 script_dependencies("ssh_detect.nasl");
 script_tag(name:"qod_type", value:"exploit");
 exit(0);
}

include("ssh_func.inc");

if( ! port = get_kb_item( "Services/ssh" ) ) exit( 0 );
if( ! get_port_state( port ) ) exit( 0 );

if( ! soc = open_sock_tcp( port ) ) exit( 0 );

user = 'root';
pass = 'avam@r';

login = ssh_login( socket:soc, login:user, password:pass, pub:NULL, priv:NULL, passphrase:NULL );

if(login == 0)
{
  cmd = ssh_cmd( socket:soc, cmd:'cat /etc/passwd', nosh:TRUE );
  close( soc );

  if( cmd =~ 'root:.*:0:[01]:' )
  {
    report = 'It was possible to login as user `root` with password `avam@r` and to execute `cat /etc/passwd`. Result:\n\n' + cmd;
    security_message( port:port, data:report );
    exit( 0 );
  }
}

if( soc ) close( soc );
exit( 0 );

