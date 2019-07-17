###############################################################################
# OpenVAS Vulnerability Test
#
# RTSP Server OS Identification
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108451");
  script_version("2019-07-16T12:33:17+0000");
  script_tag(name:"last_modification", value:"2019-07-16 12:33:17 +0000 (Tue, 16 Jul 2019)");
  script_tag(name:"creation_date", value:"2018-07-23 10:06:14 +0200 (Mon, 23 Jul 2018)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("RTSP Server OS Identification");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_dependencies("rtsp_detect.nasl");
  script_mandatory_keys("RTSP/server_or_auth_banner/available");

  script_tag(name:"summary", value:"This script performs RTSP server based OS detection.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

SCRIPT_DESC = "RTSP Server OS Identification";
BANNER_TYPE = "RTSP Server banner";

port = get_port_for_service( default:554, proto:"rtsp" );

if( server_banner = get_kb_item( "RTSP/" + port + "/server_banner" ) ) {

  # Server: IQinVision Embedded 1.0
  if( "IQinVision Embedded" >< server_banner ) {
    register_and_report_os( os:"Linux/Unix (Embedded)", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, banner:server_banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  unknown_banner = server_banner;
}

if( auth_banner = get_kb_item( "RTSP/" + port + "/auth_banner" ) ) {

  auth_banner_lo = tolower( auth_banner );

  # WWW-Authenticate: Basic realm="DahuaRtsp"
  # nb: Having Server: Rtsp Server/2.0 as its banner
  if( 'basic realm="dahuartsp"' >< auth_banner_lo ) {
    register_and_report_os( os:"Linux/Unix (Embedded)", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, banner:auth_banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( unknown_banner )
    unknown_banner += '\n';
  unknown_banner += auth_banner;
}

if( unknown_banner )
  register_unknown_os_banner( banner:unknown_banner, banner_type_name:BANNER_TYPE, banner_type_short:"rtsp_banner", port:port );

exit( 0 );
