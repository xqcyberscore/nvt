###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lantronix_device_detect_http.nasl 7933 2017-11-29 14:03:45Z cfischer $
#
# Lantronix Devices Detection Detection (HTTP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.108304");
  script_version("$Revision: 7933 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-29 15:03:45 +0100 (Wed, 29 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-11-29 12:03:31 +0100 (Wed, 29 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Lantronix Devices Detection Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script performs HTTP based detection of Lantronix Devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
buf  = http_get_cache( item:"/", port:port );

if( buf =~ "^HTTP/1\.[0-1] 200" &&
    ( '<meta http-equiv="refresh" content="1; URL=secure/ltx_conf.htm">' >< buf || 
      'var sTargetURL = "secure/ltx_conf.htm";' >< buf ||
      "<title>Lantronix WEB-Manager</title>" >< buf || 
      '<frame name="navframe" target="mainframe" src="LTX_navi.html" scrolling=no>' >< buf ) ) {

  version = "unknown";
  set_kb_item( name:"lantronix_device/http/" + port + "/version", value:version );
  set_kb_item( name:"lantronix_device/detected", value:TRUE );
  set_kb_item( name:"lantronix_device/http/detected", value:TRUE );
  set_kb_item( name:"lantronix_device/http/port", value:port );
}

exit( 0 );
