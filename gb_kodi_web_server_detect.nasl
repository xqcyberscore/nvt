###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kodi_web_server_detect.nasl 5289 2017-02-14 01:15:35Z ckuerste $
#
# Kodi Web Server Remote Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.808282");
  script_version("$Revision: 5289 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-02-14 02:15:35 +0100 (Tue, 14 Feb 2017) $");
  script_tag(name:"creation_date", value:"2016-08-08 18:13:32 +0530 (Mon, 08 Aug 2016)");
  script_name("Kodi Web Server Remote Detection");
  script_tag(name: "summary" , value: "Detection of installed version of
  Kodi Web Server.

  This script sends HTTP GET request and try to ensure the presence of 
  Kodi Web Server from the response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_summary("Check for the presence of Kodi Web Server in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 8080);
  exit(0);
}

##
### Code Starts Here
##

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variables Initialization
cpe = "";
kodiPort  = "";
kodiVer = "";

##Get HP SiteScope Port
kodiPort = get_http_port(default:8080);

##Send request and receive response
rcvRes = http_get_cache(port: kodiPort, item: "/");

## Confirm the server
if(("<title>Kodi</title>" >< rcvRes && ">Profiles<" >< rcvRes &&
   ">Remote<" >< rcvRes && ">Music<" >< rcvRes) ||
   ("Kodi web interface</title>" >< rcvRes && 'js/kodi-webinterface.js"></script>' >< rcvRes))
{
  version = "unknown";

  data = '[{"jsonrpc":"2.0","method":"Application.GetProperties","params":[["volume","muted","version"]],"id":71}]';

  req = http_post_req(port: kodiPort, url: "/jsonrpc?Application.GetProperties", data: data,
                      accept_header: "text/plain, */*; q=0.01",
                      add_headers:make_array( "Content-Type", "application/json"));
  res = http_keepalive_send_recv(port: kodiPort, data: req);

  vers = eregmatch(pattern: 'version".."major":([0-9]+),"minor":([0-9]+)', string: res);
  if (!isnull(vers[1]) && !isnull(vers[2])) {
    version = vers[1] + '.' + vers[2];
    set_kb_item(name: "Kodi/WebServer/version", value: version);
  }

  ##Set the KB
  set_kb_item(name:"Kodi/WebServer/installed", value:TRUE);

  ## build cpe and store it as host_detail
  ## created new cpe
  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:kodi:kodi_web_server:");
  if (!cpe)
    cpe = "cpe:/a:kodi:kodi_web_server";

  ##Register Product and Build Report
  register_product(cpe:cpe, location:"/", port:kodiPort);
  log_message(data: build_detection_report(app:"Kodi Web Server",
                                           version: version,
                                           install:"/",
                                           cpe:cpe,
                                           concluded: vers[0]),
              port:kodiPort);
  exit(0);
}
