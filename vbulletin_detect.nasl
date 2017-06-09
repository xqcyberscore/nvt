###############################################################################
# OpenVAS Vulnerability Test
# $Id: vbulletin_detect.nasl 6065 2017-05-04 09:03:08Z teissa $
#
# vBulletin Detection
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2014-04-24
# According to CR57 and new style script_tags.
#
# Copyright:
# Copyright (C) 2005 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.17282");
  script_version("$Revision: 6065 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-05-04 11:03:08 +0200 (Thu, 04 May 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_name("vBulletin Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of installed version of vBulletin discussion forum.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


##
## The script code starts here
##

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

## Get http port
port = get_http_port( default:80 );

## Check Host Supports PHP
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", "/forum", "/vbulletin", "/vbulletin/forum", cgi_dirs( port:port ) ) ) {

  foreach file( make_list( "/index.php", "/content.php" ) ) {

    install = dir;
    if( dir == "/" ) dir = "";

    rcvRes = http_get_cache( item:dir + file, port:port );

    if( egrep( pattern:" content=.vBulletin ", string:rcvRes, icase:TRUE ) ) {

      version = "unknown";

      ver = eregmatch( pattern:"vBulletin ([0-9.]+).*", string:rcvRes, icase:TRUE );
      if( isnull( ver[1] ) )
        ver = eregmatch( pattern:'Powered by.*vBulletin.*Version ([0-9.]+)', string: rcvRes );

      if( ! isnull( ver[1] ) ) version = ver[1];
      tmp_version = version + " under " + install;

      ## Set the KB
      set_kb_item( name:"www/" + port + "/vBulletin", value:tmp_version );
      set_kb_item( name:"vBulletin/installed", value:TRUE );

      ## build cpe and store it as host_detail
      cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:vbulletin:vbulletin:" );
      if( ! cpe )
        cpe = "cpe:/a:vbulletin:vbulletin";

      register_product( cpe:cpe, location:install, port:port );

      log_message(data:build_detection_report( app:"vBulletin",
                                                version:version,
                                                install:install,
                                                cpe:cpe,
                                                concluded:ver[1] ),
                                                port:port );
      break;
    }
  }
}

exit(0);