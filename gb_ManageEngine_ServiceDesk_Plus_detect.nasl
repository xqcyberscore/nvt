###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ManageEngine_ServiceDesk_Plus_detect.nasl 6040 2017-04-27 09:02:38Z teissa $
#
# ManageEngine ServiceDesk Plus Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2015-02-12
# According to CR57 and new style script_tags.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.103183");
  script_version("$Revision: 6040 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-04-27 11:02:38 +0200 (Thu, 27 Apr 2017) $");
  script_tag(name:"creation_date", value:"2011-06-29 13:12:40 +0200 (Wed, 29 Jun 2011)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("ManageEngine ServiceDesk Plus Detection");

  script_tag(name: "summary" , value: "Detection of installed version of
  ManageEngine ServiceDesk Plus.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_xref(name : "URL" , value : "http://www.manageengine.com/products/service-desk");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("host_details.inc");
include("cpe.inc");

## Get http port
http_port = get_http_port(default:8080);
if(!http_port)exit(0);

if(!get_port_state(http_port))exit(0);

url = string("/");
req = http_get(item:url, port:http_port);
buf = http_keepalive_send_recv(port:http_port, data:req, bodyonly:FALSE);
if(egrep(pattern:"<title>ManageEngine ServiceDesk Plus</title>", string: buf, icase: TRUE))
{
  install=string("/");
  vers = string("unknown");

  ### try to get version
  version = eregmatch(string: buf, pattern: "ManageEngine ServiceDesk Plus</a><span>&nbsp;&nbsp;\|&nbsp;&nbsp;([0-9.]+)",icase:TRUE);
  if(isnull(version[1])){
    version = eregmatch(string: buf, pattern: "ManageEngine ServiceDesk Plus','http://.*','([0-9.]+)'",icase:TRUE);
  }  
  if(!isnull(version[1])) 
  {
    vers=chomp(version[1]);
    major = vers;
  }

  build = eregmatch(string: buf, pattern: "/scripts/Login\.js\?([0-9.]+)",icase:TRUE);

  if ( !isnull(build[1]) ) {
    vers=vers + string(" Build ", build[1]);
    BUILD = build[1];
    appVer = major + '-build' + BUILD;
  } else {
    BUILD = "unknown";
    appVer = major;
  }

  set_kb_item(name: string("www/", http_port, "/ManageEngine"), value: string(vers," under ",install));
  set_kb_item(name:"ManageEngine/ServiceDeskPlus/installed", value:TRUE);

  if(appVer)
  {
    cpe = build_cpe(value:appVer, exp:"^([0-9.]+)-(build.([0-9.]+))?", base:"cpe:/a:manageengine:servicedesk_plus:");
    if(isnull(cpe)){
      cpe = "cpe:/a:manageengine:servicedesk_plus";
    }

    register_product(cpe:cpe, location:"/", port:http_port);

    log_message(data: build_detection_report(app:"ManageEngine ServiceDesk Plus",
                                             version: major,
                                             install:"/",
                                             cpe:cpe,
                                             concluded:appVer),
                                             port: http_port);
  }
}