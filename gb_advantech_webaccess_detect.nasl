##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_advantech_webaccess_detect.nasl 8078 2017-12-11 14:28:55Z cfischer $
#
# Advantech WebAccess Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804429");
  script_version("$Revision: 8078 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-12-11 15:28:55 +0100 (Mon, 11 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-04-16 14:24:35 +0530 (Wed, 16 Apr 2014)");

  script_name("Advantech WebAccess Version Detection");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Advantech WebAccess.

The script sends a connection request to the server and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

awPort = get_http_port( default:80 );
if( ! can_host_asp( port:awPort ) ) exit( 0 );

awRes = http_get_cache( item:"/broadWeb/bwRoot.asp", port:awPort );

if( "Advantech WebAccess" >!< awRes ) exit( 0 );

vers = 'unknown';
cpe = 'cpe:/a:advantech:advantech_webaccess';

awVer = eregmatch(pattern:"Software Build : ([0-9.-]+)", string:awRes);
if(!awVer[1]){
  awVer = eregmatch(pattern:"class=e5>.*: ([0-9.-]+)", string:awRes);
}

if( ! isnull( awVer[1] ) ) {
  vers = str_replace( string:awVer[1], find:"-", replace:".");
  cpe += ':' + vers;
} else {
  awVer = eregmatch(pattern: 'class="version">.*: ([0-9.-]+)', string: awRes);
  if (!isnull(awVer[1])) {
    vers = str_replace( string:awVer[1], find:"-", replace:".");
    cpe += ':' + vers;
  }
}

set_kb_item(name:"www/" + awPort + "/Advantech/WebAccess", value:vers);
set_kb_item(name:"Advantech/WebAccess/installed", value:TRUE);

## Register the product
register_product(cpe:cpe, location:awPort + '/tcp', port:awPort);

log_message(data: build_detection_report(app:"Advantech WebAccess",
                                         version:vers,
                                         install:'/broadWeb/',
                                         cpe:cpe,
                                         concluded: awVer[0]),
                                         port:awPort);

exit(0);
