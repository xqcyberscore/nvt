###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_linksys_devices_detect.nasl 7538 2017-10-24 06:46:01Z santu $
#
# Linksys Devices Remote Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.812041");
  script_version("$Revision: 7538 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-24 08:46:01 +0200 (Tue, 24 Oct 2017) $");
  script_tag(name:"creation_date", value:"2017-10-19 12:33:14 +0530 (Thu, 19 Oct 2017)");
  script_name("Linksys Devices Remote Detection");

  script_tag(name:"summary", value:"Detection of Linksys Devices.

  The script sends a connection request to the server and attempts to
  detect the presence of Linksys Devices from the response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_hnap_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 8080);
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

##Variable Initialization
netPort = "";
banner = "";
vendor = "";
model = "";
firmware = "";

##Get Port
netPort = get_kb_item("HNAP/port");
if(!netPort)
{
  netPort = get_http_port(default:80);
  if(!netPort){
    exit(0);
  }
}

##Get Vendor
vendor = get_kb_item("HNAP/vendor");
if(!vendor)
{
  ##Get http banner
  banner = get_http_banner(port:netPort);
  ##Confirm Application
  if(banner && 'WWW-Authenticate: Basic realm="Linksys' >< banner){
    vendor = "Linksys";
  } else
  {
    res = http_get_cache( item: "/", port:netPort );
    ## Confirm from response
    if("title>Linksys" >< res && "router.sys_model" >< res && "firmware" >< res
       && '">WAN IP<' >< res && '">LAN IP<' >< res){
      vendor = "Linksys";
    }
  }   
}

##Confirm Devices
else if("linksys" >< tolower(vendor))
{
  ##Set KB Linksys device present
  set_kb_item(name:"Linksys/detected", value: TRUE);

  ##Get firmware version
  firmware = get_kb_item("HNAP/firmware");
  if(!firmware){
    firmware = "Unknown";
  }

  model = get_kb_item("HNAP/model");
  if(!model)
  {
    model = eregmatch( pattern:'Basic realm="Linksys (.*)', string:banner);
    if(model[1]) model = model[1];
  }

  set_kb_item(name:"Linksys/model", value:model);
  set_kb_item(name:"Linksys/firmware", value:firmware);

  ##Assigning CPE name as cpe:/a:linksys:devices
  ## build cpe and store it as host_detail
  cpe = build_cpe(value: firmware, exp: "^([A-Za-z0-9.]+)", base: "cpe:/a:linksys:devices");
  if (!cpe)
    cpe = "cpe:/a:linksys:devices";

  register_product(cpe:cpe, location:"/", port:netPort);

  log_message(data: build_detection_report(app: "Linksys Devices",
                                           version: firmware,
                                           install: "/",
                                           cpe: cpe,
                                           concluded: firmware),
                                           port: netPort);
  exit(0);
}
