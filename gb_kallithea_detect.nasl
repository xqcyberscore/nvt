###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kallithea_detect.nasl 2898 2016-03-20 13:17:20Z cfi $
#
# Kallithea Remote Version Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806612");
  script_version("$Revision: 2898 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-03-20 14:17:20 +0100 (Sun, 20 Mar 2016) $");
  script_tag(name:"creation_date", value:"2015-11-06 12:02:52 +0530 (Fri, 06 Nov 2015)");
  script_name("Kallithea Remote Version Detection");
  script_summary("Set the version of Kallithea in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 5000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of installed version of
  Kallithea.

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
port = get_http_port( default:5000 );

##Iterate over possible paths
foreach dir( make_list_unique( "/", "/kallithea", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item: dir + "/", port:port );

  ## Confirm the application
  if( rcvRes =~ 'kallithea-scm.*>Kallithea<' && 'kallithea.css' >< rcvRes &&
                'Dashboard' >< rcvRes ) {

    version = "unknown";

    ## Grep for the version
    ver = eregmatch( pattern:'target.*>Kallithea</a> ([0-9.]+)', string:rcvRes );
    if( ver[1] ) version = ver[1];

    ## Set the KB value
    set_kb_item( name:"www/" + port + "/Kallithea", value:version );
    set_kb_item( name:"Kallithea/Installed", value:TRUE );

    ## build cpe and store it as host_detail
    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:kallithea:kallithea:" );
    if( ! cpe )
      cpe = "cpe:/a:kallithea:kallithea";

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"Kallithea",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0] ),
                                              port:port );
  }
}

exit( 0 );