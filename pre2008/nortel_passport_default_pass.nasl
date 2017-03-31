###############################################################################
# OpenVAS Vulnerability Test
# $Id: nortel_passport_default_pass.nasl 4830 2016-12-21 11:48:51Z cfi $
#
# Nortel/Bay Networks default password
#
# Authors:
# Rui Bernardino <rbernardino@oni.pt>
#
# Copyright:
# Copyright (C) 2002 Rui Bernardino
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.10989");
  script_version("$Revision: 4830 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-21 12:48:51 +0100 (Wed, 21 Dec 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Nortel/Bay Networks default password");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2002 Rui Bernardino");
  script_family("Default Accounts");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);

  tag_summary = "The remote switch/routers uses the default password.
  This means that anyone who has (downloaded) a user manual can
  telnet to it and gain administrative access.";

  tag_solution = "Telnet this switch/router and change all passwords
  (check the manual for default users)";
 
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag( name:"qod_type", value:"remote_vul" );

  exit(0);
}
 
include('telnet_func.inc');

port = get_telnet_port( default:23 );
 
banner = get_telnet_banner( port:port );
if( ! banner || "Passport" >!< banner ) exit( 0 );
 
# Although there are at least 11 (!?) default passwords to check, the passport will only allow
# 3 attempts before closing down the telnet port for 60 seconds. Fortunatelly, nothing prevents
# you to establish a new connection for each password attempt and then close it before the 3 attempts.

user[0] = "rwa";
pass[0] = "rwa";

user[1] = "rw";
pass[1] = "rw";

user[2] = "l3";
pass[2] = "l3";

user[3] = "l2";
pass[3] = "l2";

user[4] = "ro";
pass[4] = "ro";

user[5] = "l1";
pass[5] = "l1";

user[6] = "l4admin";
pass[6] = "l4admin";

user[7] = "slbadmin";
pass[7] = "slbadmin";

user[8] = "operator";
pass[8] = "operator";

user[9] = "l4oper";
pass[9] = "l4oper";

user[10] = "slbop";
pass[10] = "slbop";

PASS = 11;

for( i = 0; i < PASS; i++ ) {

  soc = open_sock_tcp( port );
  if( ! soc ) exit( 0 );
  buf = telnet_negotiate( socket:soc );

  if( "NetLogin:" >< buf ) {
    close( soc );
    exit( 0 );
  }

  if( "Passport" >< buf ) {
    if( "Login:" >< buf ) {
      test = string( user[i], "\n", pass[i], "\n" );
      send( socket:soc, data:test );
      resp = recv( socket:soc, length:1024 );

      if( "Access failure" >< resp ) {
        close( soc );
        exit( 0 );
      }

      if( ! ( "Login" >< resp ) ) {
        report = string( "Password for user ", user[i]," is ", pass[i] );
        security_message( port:port, data:report );
      }
    }
  }
  close( soc );
}

exit ( 0 );