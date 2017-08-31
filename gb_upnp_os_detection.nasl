###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_upnp_os_detection.nasl 6829 2017-08-01 12:56:19Z cfischer $
#
# UPnP Protocol OS Identification
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108200");
  script_version("$Revision: 6829 $");
  script_tag(name:"last_modification", value:"$Date: 2017-08-01 14:56:19 +0200 (Tue, 01 Aug 2017) $");
  script_tag(name:"creation_date", value:"2017-08-01 11:13:48 +0200 (Tue, 01 Aug 2017)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("UPnP Protocol OS Identification");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_upnp_detect.nasl");
  script_require_udp_ports("Services/udp/upnp", 1900);
  script_mandatory_keys("upnp/identified");

  script_tag(name:"summary", value:"This script performs UPnP protocol based OS detection.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");

SCRIPT_DESC = "UPnP Protocol OS Identification";
BANNER_TYPE = "UPnP protocol banner";

# Only covering UDP, the TCP banners are handled via sw_http_os_detection.nasl
port = get_kb_item( "Services/udp/upnp" );
if( ! port ) port = 1900;
if( ! get_udp_port_state( port ) ) exit( 0 );
if( ! banner = get_kb_item( "upnp/" + port + "/banner" ) ) exit( 0 );

if( "FRITZ!Box" >< banner ) {
  register_and_report_os( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

if( egrep( pattern:"^SERVER: Linux", string:banner, icase:TRUE ) ) {
  version = eregmatch( pattern:"Linux/([0-9.x]+)", string:banner );
  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:"Linux", version:version[1], cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

register_unknown_os_banner( banner:banner, banner_type_name:BANNER_TYPE, banner_type_short:"upnp_banner", port:port, proto:"udp" );

exit( 0 );
