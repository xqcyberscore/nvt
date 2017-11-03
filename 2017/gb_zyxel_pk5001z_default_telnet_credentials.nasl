###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zyxel_pk5001z_default_telnet_credentials.nasl 7626 2017-11-02 09:11:00Z asteins $
#
# ZyXEL PK5001Z Modem Backup Telnet Account and Default Root Credentials
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112100");
  script_version("$Revision: 7626 $");
  script_cve_id("CVE-2016-10401");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_name("ZyXEL PK5001Z Modem Backup Telnet Account and Default Root Credentials");
  script_tag(name:"last_modification", value:"$Date: 2017-11-02 10:11:00 +0100 (Thu, 02 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-11-02 09:19:00 +0200 (Thu, 02 Nov 2017)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/43105/");
  script_xref(name:"URL", value:"https://forum.openwrt.org/viewtopic.php?id=62266");

  script_tag(name:"summary", value:"The ZyXEL PK5001Z modem has default root credentials set and a backdoor account with hard-coded credentials.");
  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain full
  access to sensitive information or modify system configuration.");
  script_tag(name:"vuldetect", value:"Connect to the telnet service and try to login with default credentials.");
  script_tag(name:"insight", value:"It was possible to login with backup telnet credentials 'admin:CeturyL1nk'.
  Furthermore it was also possible to gain root privileges with the 'su' command the the root password 'zyad5001'.");
  script_tag(name:"solution", value:"It is recommended to disable the telnet access and change the backup and default credentials.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("telnet_func.inc");

port = get_kb_item("Services/telnet");
if( ! port ) port = 23;
if( ! get_port_state( port ) ) exit( 0 );

banner = get_telnet_banner( port:port );

if( "PK5001Z login:" >!< banner ) exit( 0 );

login = "admin";
pass = "CenturyL1nk";
root_pass = "zyad5001";

report = "";

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

recv = recv( socket:soc, length:2048 );

if ( "PK5001Z login:" >< recv ) {
  send( socket:soc, data: tolower( login ) + '\r\n' );
  recv = recv( socket:soc, length:128 );

  if( "Password:" >< recv ) {
    send( socket:soc, data: pass + '\r\n\r\n' );
    recv = recv( socket:soc, length:1024 );

    send( socket:soc, data: 'whoami\r\n' );
    recv = recv( socket:soc, length:1024 );

    if( recv  =~ "admin" ) {
      VULN = TRUE;
      report += 'It was possible to login via telnet using the following backup credentials:\n';
      report += 'PK5001Z login: ' + login + ', Password: ' + pass;
    }

    send( socket:soc, data: 'su\r\n' );
    recv = recv( socket:soc, length:1024 );

    send( socket:soc, data: root_pass + '\r\n' );
    recv = recv( socket:soc, length:1024 );

    send( socket:soc, data: 'cat /etc/zyfwinfo\r\n' );
    recv = recv( socket:soc, length:1024 );

    if( recv =~ "ZyXEL Communications Corp." ) {
      VULN = TRUE;
      report += '\n\nIt was possible to escalate to root privileges with the following root password: ' + root_pass;
    }
  }
}

close( soc );

if( VULN ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
