###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netis_netcore_backdoor_09_2014.nasl 8236 2017-12-22 10:28:23Z cfischer $
#
# Backdoor Access To Netcore/Netis Devices
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105075");
  script_version("$Revision: 8236 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-12-22 11:28:23 +0100 (Fri, 22 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-09-01 12:03:46 +0200 (Mon, 01 Sep 2014)");
  script_name("Backdoor Access To Netcore/Netis Devices");
  script_category(ACT_ATTACK);
  script_family("General");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_require_udp_ports(53413);

  script_xref(name:"URL", value:"http://blog.trendmicro.com/trendlabs-security-intelligence/netis-routers-leave-wide-open-backdoor/");

  script_tag(name:"impact", value:"Clients can leverage this service to execute arbitrary commands on the
  underlying system");

  script_tag(name:"vuldetect", value:"Send a special request to udp port 53413 and check the response.");

  script_tag(name:"insight", value:"Affected devices include a backdoor service listening on UDP port 53413");

  script_tag(name:"solution", value:"Ask the Vendor for an update");

  script_tag(name:"summary", value:"Backdoor access to Netcore/Netis devices");

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

port = 53413;
if( ! get_udp_port_state( port ) ) exit( 0 );
if( ! soc = open_sock_udp( port ) ) exit( 0 );

send( socket:soc, data:'' );
recv = recv( socket:soc, length:64, timeout:3 );

if( "Login:" >!< recv ) exit( 0 );

send( socket:soc, data:'XXXXXXXXnetcore' );
recv = recv( socket:soc, length:128, timeout:3 );

close( soc );

if( "Login successed" >< recv ) {
  security_message( port:port, proto:'udp' );
  exit( 0 );
}

exit( 99 );
