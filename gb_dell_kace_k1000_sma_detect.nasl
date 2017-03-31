###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dell_kace_k1000_sma_detect.nasl 5390 2017-02-21 18:39:27Z mime $
#
# Dell Kace K1000 Systems Management Appliance (SMA) Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803734";

if (description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 5390 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-02-21 19:39:27 +0100 (Tue, 21 Feb 2017) $");
  script_tag(name:"creation_date", value:"2013-08-12 19:47:34 +0530 (Mon, 12 Aug 2013)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Dell Kace K1000 Systems Management Appliance (SMA) Detection");

  tag_summary =
"The script sends a connection request to the server and attempts to
extract the version number from the reply.";


  script_tag(name : "summary" , value : tag_summary);

  script_summary("Checks for the presence of Dell Kace K1000 Systems Management Appliance");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_require_ports("Services/www", 80);
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("k1000/banner");
  exit(0);
}


include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable initialization
port = "";
banner = "";
version = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

## Get the banner
banner = get_http_banner(port: port);

## Confirm the application
if("X-DellKACE-Appliance: k1000" >< banner)
{


  version = eregmatch(string: banner, pattern: "X-DellKACE-Version: ([0-9.]+)");
  if(version[1])
  {
    set_kb_item(name:"X-DellKACE/installed",value:TRUE);

    ## Set the version
    set_kb_item(name: string("www/", port, "/X-DellKACE"), value: version[1]);

    ## build CPE
    cpe = build_cpe(value:version[1], exp:"^([0-9.]+)", base:"cpe:/a:dell:x_dellkace:");
    if(isnull(cpe))
      cpe = 'cpe:/a:dell:x_dellkace';

    ## Register the product
    register_product(cpe:cpe, location:'/http', nvt:SCRIPT_OID, port:port);

    log_message(data: build_detection_report(app:"Dell Kace k1000",
                                             version:version[1],
                                             install:'/http',
                                             cpe:cpe,
                                             concluded: version[1]),
                                             port:port);
  }
}
