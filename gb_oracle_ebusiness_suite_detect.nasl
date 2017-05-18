###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_ebusiness_suite_detect.nasl 6049 2017-04-28 11:07:48Z antu123 $
#
# Oracle E-Business Suite Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811015");
  script_version("$Revision: 6049 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-04-28 13:07:48 +0200 (Fri, 28 Apr 2017) $");
  script_tag(name:"creation_date", value:"2017-04-27 10:34:57 +0530 (Thu, 27 Apr 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Oracle E-Business Suite Detection");
  script_tag(name: "summary" , value: "Detection of installed version of
  Oracle E-Business Suite Detection.

  This script sends HTTP GET request and try to get the version from the
  response.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

##
### Code Starts Here
##

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variables Initialization
cpe = "";
req = "";
res = "";
oPort  = "";
oVer = "";

##Get OAT Port
oPort = get_http_port(default:443);
if(!oPort){
  exit(0);
}

##Send first request
res = http_get_cache(port: oPort, item: "/");

##Confirm Application
if(res && ">E-Business Suite Home Page Redirect<" >< res && "The E-Business Home Page" >< res)
{
  set_kb_item(name:"Oracle/eBusiness/Suite/Installed", value:TRUE);

  oVer = "unknown";

  cpe = "cpe:/a:oracle:e-business_suite";

  register_product( cpe:cpe, location:"/", port:oPort);
  log_message( data: build_detection_report( app: "Oracle E-Business Suite",
                                           version: oVer,
                                           install: "/",
                                           cpe: cpe,
                                           concluded: oVer),
                                           port: oPort);
}
