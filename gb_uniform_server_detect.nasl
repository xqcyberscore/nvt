###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_uniform_server_detect.nasl 6063 2017-05-03 09:03:05Z teissa $
#
# Uniform Server Version Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800786");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 6063 $");
  script_tag(name:"last_modification", value:"$Date: 2017-05-03 11:03:05 +0200 (Wed, 03 May 2017) $");
  script_tag(name:"creation_date", value:"2010-06-04 09:43:24 +0200 (Fri, 04 Jun 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Uniform Server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script finds the installed Uniform Server version and saves
  the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

uniPort = get_http_port(default:80);

## Send and receive response
rcvRes = http_get_cache(item:"/", port:uniPort);

## Confirm the application
if( ">Uniform Server" >< rcvRes ) {

  version = "unknown";
  install = "/";

  ## Grep for the version
  ver = eregmatch( pattern:"Uniform Server (([0-9.]+).?([a-zA-Z]+))", string:rcvRes );
  if( ver[1] != NULL ) version = ver[1];

  ## Set the KB value
  set_kb_item( name:"www/" + uniPort + "/Uniform-Server", value:version );

  ## build cpe and store it as host_detail
  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:uniformserver:uniformserver:" );
  if( isnull( cpe ) )
    cpe = 'cpe:/a:uniformserver:uniformserver';

  ## Register Product and Build Report
  register_product( cpe:cpe, location:install, port:uniPort );

  log_message( data:build_detection_report( app:"Uniform Server",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:ver[0] ),
                                            port:uniPort );
}

exit( 0 );