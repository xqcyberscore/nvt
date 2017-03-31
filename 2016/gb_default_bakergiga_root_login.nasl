###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_default_bakergiga_root_login.nasl 4509 2016-11-15 07:51:06Z mime $
#
# Default password `bakergiga` for root account
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
 script_oid("1.3.6.1.4.1.25623.1.0.140055");
 script_version("$Revision: 4509 $");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Default password `bakergiga` for root account");
 script_tag(name:"last_modification", value:"$Date: 2016-11-15 08:51:06 +0100 (Tue, 15 Nov 2016) $");
 script_tag(name:"creation_date", value:"2016-11-15 08:49:09 +0100 (Tue, 15 Nov 2016)");
 script_category(ACT_ATTACK);
 script_family("Default Accounts");
 script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
 script_require_ports("Services/ssh", 22);

 script_tag(name: "summary" , value: 'The remote device is prone to a default account authentication bypass vulnerability.');

 script_tag(name: "impact" , value:'This issue may be exploited by a remote attacker to gain access to sensitive information or modify system configuration.');

 script_tag(name: "vuldetect" , value: 'Try to login as root with password `bakergiga`.');
 script_tag(name: "solution" , value: 'Change the password');
 script_tag(name:"solution_type", value:"Workaround");
 script_dependencies("ssh_detect.nasl");
 script_tag(name:"qod_type", value:"exploit");
 exit(0);
}

include("ssh_func.inc");

port = get_kb_item( "Services/ssh" );
if( ! port ) port = 22;

if( ! get_port_state( port ) ) exit( 0 );

if( ! soc = open_sock_tcp( port ) ) exit( 0 );

user = 'root';
pass = 'bakergiga';

login = ssh_login( socket:soc, login:user, password:pass, pub:NULL, priv:NULL, passphrase:NULL );

if(login == 0)
{
  cmd = ssh_cmd( socket:soc, cmd:'version', pty:TRUE, nosh:TRUE, pattern:'Current Image Version' );

  close( soc );

  if( "Current Image Version" >< cmd )
  {
    report = 'It was possible to login as user `root` with password `bakergiga` and to execute the `version` command. Result:\n\n' + cmd;
    security_message( port:port, data:report );
    exit( 0 );
  }
}

if( soc ) close( soc );
exit( 0 );

