###############################################################################
# OpenVAS Vulnerability Test
#
# ManageUPSNET UPS / USV Telnet Default Credentials
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.113049");
  script_version("2019-06-06T07:39:31+0000");
  script_tag(name:"last_modification", value:"2019-06-06 07:39:31 +0000 (Thu, 06 Jun 2019)");
  script_tag(name:"creation_date", value:"2017-11-09 15:05:05 +0100 (Thu, 09 Nov 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("ManageUPSNET UPS / USV Telnet Default Credentials");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/manageupsnet/detected");

  script_tag(name:"summary", value:"ManageUPSNET Telnet and FTP uses remote credentials 'admin' - 'admin'.");

  script_tag(name:"vuldetect", value:"The script tries to login via Telnet using the username 'admin' and the password 'admin'.");

  script_tag(name:"impact", value:"Successful exploitation would allow to gain complete administrative access to the host.");

  script_tag(name:"affected", value:"All ManageUPSNET devices version 2.6 or later.");

  script_tag(name:"solution", value:"Change the default password for the administrative account 'admin' for both Telnet and FTP.");

  script_xref(name:"URL", value:"http://005c368.netsolhost.com/pdfs/9133161c.pdf");

  exit(0);
}

include("telnet_func.inc");
include("misc_func.inc");
include("dump.inc");

port = telnet_get_port( default:23 );
banner = telnet_get_banner( port:port );
if( !banner || "ManageUPSnet" >!< banner )
  exit( 0 );

login = "admin";
pass = "admin";

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

recv = recv( socket: soc, length: 2048 );

if( "User Name :" >< recv ) {
  send( socket: soc, data: tolower( login ) + '\r\n' );
  recv = recv( socket: soc, length: 128 );

  if( "Password  :" >< recv || "Password :" >< recv ) {
    send( socket: soc, data: pass + '\r\n\r\n' );
    recv = recv( socket: soc, length: 1024 );

    if( "UPS Name:" >< recv && "UPS Model:" >< recv) {
      VULN = TRUE;
      report = 'It was possible to login via telnet using the following default credentials:\n\n';
      report += 'Login: ' + login + ', Password: ' + pass;
    }
  }
}

close( soc );

if( VULN ) {
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
