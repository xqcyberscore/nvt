##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_freeproxy_internet_suite_detect.nasl 4886 2016-12-30 12:19:10Z antu123 $
#
# Freeproxy Internet Suite Detection
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.806894");
  script_version("$Revision: 4886 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-12-30 13:19:10 +0100 (Fri, 30 Dec 2016) $");
  script_tag(name:"creation_date", value:"2016-05-17 11:03:06 +0530 (Tue, 17 May 2016)");
  script_name("Freeproxy Internet Suite Detection");
  script_tag(name:"summary", value:"Detection of installed version
  of Freeproxy Internet Suit.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");
  
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

##Varriable initialize
freePort = 0;
rcvRes = "";
version = "";
freeVer = "";

#Get port
freePort = get_http_port(default:8080);
if(!freePort){
  freePort = 8080;
}

##check port state
if(!get_port_state(freePort)){
  exit(0);
}

##Get banner response
if(!rcvRes = http_get_cache( item:'/', port:freePort )){
  exit(0);
}

##Confirm application
if('Server: FreeProxy' >< rcvRes)
{
   freeVer = eregmatch(pattern:"Server: FreeProxy/([0-9.]+)", string:rcvRes);

   if(freeVer[1]){
	version = freeVer[1];
   } else {
	version = "Unknown";
   }
  
   ## Set Kb
   set_kb_item(name:"Freeproxy/installed", value:TRUE);
   set_kb_item(name:"Freeproxy/Ver", value:version);
 
   ## build cpe and store it as host_detail
   cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:freeproxy_internet_suite:freeproxy:");
   if(!cpe)
      cpe= "cpe:/a:freeproxy_internet_suite:freeproxy";

   register_product(cpe:cpe, location:"/", port:freePort);

   log_message(data: build_detection_report(app: "Freeproxy internet suite",
                                            version: version,
                                            install: "/",
                                            cpe: cpe,
                                            concluded: version),
                                            port: freePort);
   exit(0);
}
