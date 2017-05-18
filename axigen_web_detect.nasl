###############################################################################
# OpenVAS Vulnerability Test
# $Id: axigen_web_detect.nasl 6032 2017-04-26 09:02:50Z teissa $
#
# Axigen Web Detection
#
# Authors:
# Michael Meyer
#
# Updated By Shakeel <bshakeel@secpod.com> on 07-07-2014
# According to CR57 and new script style
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100176");
  script_version("$Revision: 6032 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-04-26 11:02:50 +0200 (Wed, 26 Apr 2017) $");
  script_tag(name:"creation_date", value:"2009-05-02 19:46:33 +0200 (Sat, 02 May 2009)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Axigen Web Detection");

  tag_summary =
"Detection of installed version of Axigen.

This script sends HTTP GET request and try to get the version from the
response, and sets the result in KB.";


  script_tag(name : "summary" , value : tag_summary);

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("cpe.inc");
include("host_details.inc");

## Variable Initialization
axPort = "";
req = "";
buf= "";
app_found = "";
version = "";

## Get http port
axPort = get_http_port(default:80);
if(!axPort){
  axPort = 80;
}

## Check the port status
if(!get_port_state(axPort)){
  exit(0);
}

##Construct URL
url = string("/index.hsp?login=");

##Send the Request
req = http_get(item:url, port:axPort);
buf = http_keepalive_send_recv(port:axPort, data:req, bodyonly:FALSE);

if( buf == NULL ) exit(0);

if(egrep(pattern: 'Server: Axigen-.*', string: buf, icase: TRUE) )
{
  app_found = eregmatch(string: buf, pattern: 'Server: Axigen-(Webmail|Webadmin)',icase:TRUE);
  axigen_app = app_found[1];

  vers = string("unknown");
  ### try to get version.
  version = eregmatch(string: buf, pattern: '<title>AXIGEN Web[mail|admin]+[^0-9]+([0-9.]+)</title>',icase:TRUE);

  if (version[1]){
    vers=version[1];
  }
  else
  {
    version = eregmatch(string: buf, pattern:">[V|v]ersion ([0-9.]+)<");
    if(version)vers=version[1];
  }

  tmp_version = string(vers," under /");
  set_kb_item(name: string("www/", axPort, "/axigen"), value: tmp_version);
  set_kb_item(name:"axigen/installed", value:TRUE);

  ## build cpe and store it as host_detail
  cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:gecad_technologies:axigen_mail_server:");
  if(isnull(cpe))
    cpe = "cpe:/a:gecad_technologies:axigen_mail_server";

  register_product(cpe:cpe, location:"/", port:axPort);

  log_message(data: build_detection_report(app:"Axigen", version:vers, install:"/",
                                           cpe:cpe, concluded:vers));
}
