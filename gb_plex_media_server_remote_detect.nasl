###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_plex_media_server_remote_detect.nasl 2664 2016-02-16 07:43:49Z antu123 $
#
# Plex Media Server Remote Version Detection
#
# Authors:
# Shakeel  <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805225");
  script_version("$Revision: 2664 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-02-16 08:43:49 +0100 (Tue, 16 Feb 2016) $");
  script_tag(name:"creation_date", value:"2014-12-22 16:04:12 +0530 (Mon, 22 Dec 2014)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Plex Media Server Remote Version Detection");

  script_tag(name: "summary" , value: "Detection of installed version of Plex
  Media Server.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_summary("Checks for the presence of Plex Media Server");
  script_xref(name : "URL" , value : "https://plex.tv");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 32400);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

# Variable Initialization
sndReq = "";
rcvRes = "";
version = "";
install = "/";
plexPort = "";
url = "/web/index.html";

plexPort = get_http_port(default:32400);
if(!plexPort){
  plexPort = 32400;
}

if(!get_port_state(plexPort)){
  exit(0);
}

##Send and Receive Response
sndReq = http_get(item:url, port:plexPort);
rcvRes = http_keepalive_send_recv(port:plexPort, data:sndReq);

##Confirm Application
if(rcvRes && ">Plex" >< rcvRes && "X-Plex-Protocol" >< rcvRes)
{
  sndReq = http_get(item:install, port:plexPort);
  rcvRes = http_keepalive_send_recv(port:plexPort, data:sndReq);

  ##Grep version
  version = eregmatch(string:rcvRes, pattern:"myPlex.*version=.([0-9.]+.[a-zA-Z0-9]+)",
                                     icase:TRUE);

  ##Check if version information is available
  if(version[1]){
    version = version[1];
  }
  else{
    version = "Unknown";
  }

  set_kb_item(name: string("www/", plexPort, "/plex_media_server"), value: string(version," under ",install));
  set_kb_item(name:"plex_media_server/installed", value:TRUE);

  ##Build CPE and Register
  cpe = build_cpe(value:version, exp:"^([0-9.]+.[a-zA-Z0-9]+)", base:"cpe:/a:plex:plex_media_server:");
  if(isnull(cpe))
    cpe = 'cpe:/a:plex:plex_media_server';

  register_product(cpe:cpe, location:install, port:plexPort);

  log_message(data: build_detection_report(app:"Plex Media Server",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded: version),
  port:plexPort);
  exit(0);
}
