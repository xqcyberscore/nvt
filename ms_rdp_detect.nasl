###############################################################################
# OpenVAS Vulnerability Test
# $Id: ms_rdp_detect.nasl 8146 2017-12-15 13:40:59Z cfischer $
#
# Microsoft Remote Desktop Protocol Detection 
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100062");
  script_version("$Revision: 8146 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-15 14:40:59 +0100 (Fri, 15 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-03-19 19:54:28 +0100 (Thu, 19 Mar 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Microsoft Remote Desktop Protocol Detection");  
  script_category(ACT_GATHER_INFO);
  script_family("Windows");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 3389);

  script_tag(name:"summary", value:"The Microsoft Remote Desktop Protocol (RDP) is running at this host. Remote
  Desktop Services, formerly known as Terminal Services, is one of the components
  of Microsoft Windows (both server and client versions) that allows a user to
  access applications and data on a remote computer over a network.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("host_details.inc");

port = get_unknown_port( default:3389 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

# found in amap (http://freeworld.thc.org/thc-amap) appdefs.trig
req = raw_string( 0x03, 0x00, 0x00, 0x0b, 0x06,
                  0xe0, 0x00, 0x00, 0x00, 0x00, 0x00 );

send( socket:soc, data:req );
buf = recv( socket:soc, length:5 );
close( soc );
if( isnull( buf ) || strlen( buf ) < 5 ) exit( 0 );

response = hexstr( buf );

if( response =~ "^0300000b06$" ) {
  register_and_report_os( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:"Microsoft Remote Desktop Protocol", port:port, desc:"Microsoft Remote Desktop Protocol Detection", runs_key:"windows" );
  set_kb_item( name:"msrpd/detected", value:TRUE );
  register_service( port:port, proto:"msrdp" );
  log_message( port:port );
}

exit( 0 );
