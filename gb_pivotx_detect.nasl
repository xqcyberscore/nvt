###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pivotx_detect.nasl 6292 2017-06-08 06:36:42Z ckuersteiner $
#
# PivotX Version Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801734");
  script_version("$Revision: 6292 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-06-08 08:36:42 +0200 (Thu, 08 Jun 2017) $");
  script_tag(name:"creation_date", value:"2011-02-08 15:34:31 +0100 (Tue, 08 Feb 2011)");
  script_name("PivotX Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Product detection");
  script_require_ports("Services/www", 80);
  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of installed version of PivotX.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

##Get HTTP Port
port = get_http_port( default:80 );

# Check Host Supports PHP
if( ! can_host_php( port:port ) ) exit( 0 );

##Iterate over possible paths
foreach dir( make_list_unique( "/", "/pivotx", "/PivotX", "/blog", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item: dir + "/index.php", port:port );

  ## Confirm the application
  if ('<meta name="generator" content="PivotX"' >< rcvRes) {

    version = "unknown";

    ## Grep for the version
    ver = eregmatch( pattern:"PivotX - ([0-9.]+)", string:rcvRes) ;
    if( ver[1] != NULL ) {
      version = ver[1];
      set_kb_item(name: "PivotX/version", value: version);
    }

    set_kb_item( name:"PivotX/Installed", value:TRUE );

    ## build cpe and store it as host_detail
    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:pivotx:pivotx:" );
    if( ! cpe )
      cpe= "cpe:/a:pivotx:pivotx";

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"PivotX",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0] ),
                                              port:port );
  }
}

exit( 0 );
