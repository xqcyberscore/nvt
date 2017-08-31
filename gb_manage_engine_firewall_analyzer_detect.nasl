###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manage_engine_firewall_analyzer_detect.nasl 6796 2017-07-25 05:18:17Z santu $
#
# ManageEngine Firewall Analyzer Detection
#
# Authors:
# Rinu Kuriakose <secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
 script_oid("1.3.6.1.4.1.25623.1.0.811533");
 script_version("$Revision: 6796 $");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"last_modification", value:"$Date: 2017-07-25 07:18:17 +0200 (Tue, 25 Jul 2017) $");
 script_tag(name:"creation_date", value:"2017-07-19 13:54:26 +0530 (Wed, 19 Jul 2017)");
 script_name("ManageEngine Firewall Analyzer Detection");

 script_tag(name: "summary" , value: "Detection of installed version
 of ManageEngine Firewall Analyzer.

This script sends HTTP GET request and try to get the version from the
response, and sets the result in KB.");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

## Variable initialization
version = "";
url = "";
buf = "";

## Get HTTP Port
http_port = get_http_port(default:8500);
if(!http_port){
  http_port = 8500;
}

## Check Port state and support PHP
if(!get_port_state(http_port))exit(0);

url = string("/apiclient/ember/Login.jsp");
req = http_get(item:url, port:http_port);
buf = http_keepalive_send_recv(port:http_port, data:req, bodyonly:FALSE);

## confirm the application
if("Firewall Analyzer" >< buf && buf =~ ">Firewall Log Analytics Software from ManageEngine.*Copyright.*ZOHO Corp")
{
  version = "unknown";
 
  set_kb_item(name:"Firewall/Analyzer/installed",value:TRUE);

  ### try to get version
  version = eregmatch(string: buf, pattern: "Firewall Analyzer<span>v ([0-9.]+)</span>",icase:TRUE);
  if(!version){
    exit(0);
  }  

  if(version[1]){
    version = version[1];
  }

  ## Build CPE
  cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:zohocorp:manageengine_firewall_analyzer:");
  if(!cpe) {
    cpe = 'cpe:/a:zohocorp:manageengine_firewall_analyzer';
  }

  ## Register Product and Build Report
  register_product(cpe:cpe, location:"/", port:http_port);

  log_message(data: build_detection_report(app: "ManageEngine Firewall Analyzer",
                                             version:version,
                                             install:"/",
                                             cpe:cpe,
                                             concluded:version),
                                             port:http_port);

  exit(0);
}
