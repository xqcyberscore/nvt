###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zte_zxdsl_831CII_telnet_detect.nasl 8158 2017-12-18 13:18:20Z cfischer $
#
# ZTE ZXDSL 831CII Detection (Telnet)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
 script_oid("1.3.6.1.4.1.25623.1.0.811354");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version ("$Revision: 8158 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-18 14:18:20 +0100 (Mon, 18 Dec 2017) $");
 script_tag(name:"creation_date", value:"2017-11-28 16:53:25 +0530 (Tue, 28 Nov 2017)");
 script_name("ZTE ZXDSL 831CII Detection (Telnet)");

 script_tag(name: "summary" , value:"The script sends a connection request to 
 the server and attempts to confirm application and detect version from the 
 reply.");

 script_tag(name:"qod_type", value:"remote_banner");

 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
 script_dependencies("telnetserver_detect_type_nd_version.nasl");
 script_require_ports("Services/telnet", 23);
 exit(0);
}


include("telnet_func.inc");
include("host_details.inc");
include("cpe.inc");

ztport = get_kb_item("Services/telnet");
if(!ztport) ztport = 23;

banner = get_telnet_banner(port:ztport);

if(!banner || "Welcome to ZXDSL 831CII" >!< banner) exit( 0 );

vers = 'unknown';

set_kb_item( name:'ZXDSL_831CII/Installed', value:TRUE );

version = eregmatch(pattern:'ZTE Inc., Software Release ZXDSL 831CIIV([0-9a-zA-Z_.]+)', string:banner);

if(version[1])
{
  vers = version[1];
  set_kb_item( name:'ZXDSL_831CII/telnet/version', value:vers );
}

register_and_report_cpe( app:"ZTE ZXDSL 831CII", ver:vers, concluded:version, base:"cpe:/h:zte:zxdsl_831CII:", expr:"([0-9a-zA-Z_.]+)", insloc:"/", regPort:ztport );

exit(0);
