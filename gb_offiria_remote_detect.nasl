###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_offiria_remote_detect.nasl 7000 2017-08-24 11:51:46Z teissa $
#
# Offiria Open Source Enterprise Social Network Remote Detection
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805195");
  script_version("$Revision: 7000 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-08-24 13:51:46 +0200 (Thu, 24 Aug 2017) $");
  script_tag(name:"creation_date", value:"2015-06-09 16:51:06 +0530 (Tue, 09 Jun 2015)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_name("Offiria Open Source Enterprise Social Network Remote Detection");

  script_tag(name:"summary", value:"Detection of installed version of
  Offiria Open Source Enterprise Social Network.

  This script sends HTTP GET request and try to confirm the application from
  the response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

## Get HTTP Port
port = get_http_port( default:80 );

## Check Host Supports PHP
if( ! can_host_php( port:port ) ) exit(0);

# Iterate over possible paths
foreach dir( make_list_unique( "/", "/offiria", "/social", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item: dir + "/index.php", port:port );

  #Confirm application
  if( rcvRes =~ "HTTP/1.. 200" && ">Offiria<" >< rcvRes ) {

    ## Not able to get version without login
    ver = "Unknown";

    ## Set the KB
    set_kb_item( name:"offiria/installed", value:TRUE );

    ## build cpe and store it as host_detail
    cpe = "cpe:/a:slashes&dots:offria";

    register_product( cpe:cpe, location:install, port:port );
    log_message( data: build_detection_report( app:"Offiria",
                                               version:ver,
                                               install:install,
                                               cpe:cpe ),
                                               port:port );
  }
}

exit( 0 );