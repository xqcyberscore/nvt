###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_karaf_default_ssh_login.nasl 11650 2018-09-27 10:32:13Z jschulte $
#
# Apache Karaf SSH Default Credentials
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
  script_oid("1.3.6.1.4.1.25623.1.0.105593");
  script_version("$Revision: 11650 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Apache Karaf SSH Default Credentials");
  script_tag(name:"last_modification", value:"$Date: 2018-09-27 12:32:13 +0200 (Thu, 27 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-04-01 15:59:09 +0200 (Fri, 01 Apr 2016)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_require_ports("Services/ssh", 8101);

  script_tag(name:"summary", value:'The remote Apache Karaf is prone to a default account authentication bypass vulnerability.');

  script_tag(name:"impact", value:'This issue may be exploited by a remote attacker to gain access to sensitive information or modify system configuration.');

  script_tag(name:"vuldetect", value:'Try to login with default credentials.');
  script_tag(name:"insight", value:'It was possible to login with default credentials: karaf/karaf');
  script_tag(name:"solution", value:'Change the password.');
  script_tag(name:"solution_type", value:"Workaround");
  script_dependencies("find_service.nasl", "os_detection.nasl");
  script_tag(name:"qod_type", value:"exploit");
  exit(0);
}

include("ssh_func.inc");
include("misc_func.inc");

port = get_kb_item( "Services/ssh" );
if( ! port ) port = 8101;

if( ! get_port_state( port ) ) exit( 0 );

if( ! soc = open_sock_tcp( port ) ) exit( 0 );

user = 'karaf';
pass = 'karaf';

login = ssh_login( socket:soc, login:user, password:pass, pub:NULL, priv:NULL, passphrase:NULL );

if(login == 0)
{

  files = traversal_files();

  foreach pattern( keys( files ) ) {

    file = files[pattern];

    cmd = ssh_cmd( socket:soc, cmd:'cat /' + file, nosh:TRUE );

    if( egrep( string:cmd, pattern:pattern ) )
    {
      if( soc ) close( soc );
      report = 'It was possible to login as user `karaf` with password `karaf` and to execute `cat /' + file + '`. Result:\n\n' + cmd;
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

if( soc ) close( soc );
exit( 99 );

