###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pfsense_remote_detect.nasl 5829 2017-04-03 07:00:29Z cfi $
#
# Pfsense Remote Version Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.806807");
  script_version("$Revision: 5829 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-04-03 09:00:29 +0200 (Mon, 03 Apr 2017) $");
  script_tag(name:"creation_date", value:"2016-01-14 18:46:02 +0530 (Thu, 14 Jan 2016)");
  script_name("Pfsense Remote Version Detection");

  script_tag(name : "summary" , value : "Detection of installed version
  of pfsense.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("cpe.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
sndReq = "";
rcvRes = "";
pfsPort = "";
pfsVer = "";

pfsPort = get_http_port(default:443);

rcvRes = http_get_cache(item:"/", port:pfsPort);

## Confirm application
if('pfsense' >< rcvRes && ('>Login to pfSense<' >< rcvRes || 
   '/themes/pfsense_ng' >< rcvRes))
{
  ## Set the KB value
  set_kb_item(name:"pfsense/Installed", value:TRUE);

  ## version info is not available
  vers = 'unknown';
   
  ## build cpe and store it as host_detail
  cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:pfsense:pfsense:");
  if(!cpe)
     cpe = 'cpe:/a:pfsense:pfsense';

   register_product(cpe:cpe, location:"/", port:pfsPort);
   log_message(data: build_detection_report(app: "pfsense",
                                            version: vers,
                                            install: "/",
                                            cpe: cpe,
                                            concluded: vers,
                                            port: pfsPort));
}
