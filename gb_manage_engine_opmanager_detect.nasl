###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manage_engine_opmanager_detect.nasl 5499 2017-03-06 13:06:09Z teissa $
#
# Zoho ManageEngine OpManager Detection
#
# Authors:
# Rinu Kuriakose <secpod.com>
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

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.805471");
 script_version("$Revision: 5499 $");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"last_modification", value:"$Date: 2017-03-06 14:06:09 +0100 (Mon, 06 Mar 2017) $");
 script_tag(name:"creation_date", value:"2015-03-20 11:52:44 +0530 (Fri, 20 Mar 2015)");
 script_name("Zoho ManageEngine OpManager Detection");

 script_tag(name: "summary" , value: "Detection of installed version and build
 of ManageEngine OpManager Detection.

This script sends HTTP GET request and try to get the version from the
response, and sets the result in KB.");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

## Variable initialization
vers = string("unknown");
version = "";
cookie_new = "";
url = "";
oput = "";
apiKey = "";
major = "";
BUILD = "";

## Get HTTP Port
http_port = get_http_port(default:80);
if(!http_port){
  http_port = 80;
}

## Check Port state and support PHP
if(!get_port_state(http_port))exit(0);

url = string("/LoginPage.do");
req = http_get(item:url, port:http_port);
buf = http_keepalive_send_recv(port:http_port, data:req, bodyonly:FALSE);

if("ManageEngine" >< buf && ">OpManager<" >< buf)
{
  ### try to get version
  version = eregmatch(string: buf, pattern: ">OpManager<.*>( )?v.([0-9.]+)",icase:TRUE);
  install=string("/");
  if ( !isnull(version[2]) ) {
      vers=chomp(version[2]);
  }

  tmp_version = vers + " under " + install;

  ## Set the KB
  set_kb_item(name:"www/" + http_port + "/OpManager", value:tmp_version);
  set_kb_item(name:"OpManager/installed",value:TRUE);

  ## Build CPE
  cpe = build_cpe(value:vers, exp:"^([0-9 a-z.]+)", base:"cpe:/a:zohocorp:manageengine_opmanager:");
  if(!cpe) {
    cpe = 'cpe:/a:zohocorp:manageengine_opmanager';
  }

  ## Register Product and Build Report
  register_product(cpe:cpe, location:install, port:http_port);
  log_message(data: build_detection_report(app: "Manage Engine OpManager",
                                             version:vers,
                                             install:install,
                                             cpe:cpe,
                                             concluded:vers),
                                             port:http_port);

  exit(0);
}
