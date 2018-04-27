###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_dap_detect.nasl 9633 2018-04-26 14:07:08Z jschulte $
#
# Dlink DAP Devices Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.810234");
  script_version("$Revision: 9633 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-26 16:07:08 +0200 (Thu, 26 Apr 2018) $");
  script_tag(name:"creation_date", value:"2016-12-09 15:22:03 +0530 (Fri, 09 Dec 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Dlink DAP Devices Detection");
  script_tag(name: "summary" , value: "Detection of Dlink DAP Devices.

  The script sends a connection request to the server and attempts to
  determine if the remote host is a Dlink DAP device from the reply.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

dlPort = get_http_port(default:80);

buf = http_get_cache( item:"/", port:dlPort );

if((buf =~ 'Product Page:.*>DAP' || 'Product Page :.*>DAP') &&
   (buf =~ ">Copyright.*D-Link Systems, Inc" || ("<title>D-LINK SYSTEMS, INC. | WIRELESS AP : LOGIN</title>" >< buf)))
{
  ver = "unknown";
  model = "unknown";

  model = eregmatch( pattern:'>DAP-([0-9.]+)', string:buf );
  if(model[1]){
    set_kb_item( name:"dlink/dap/model", value:model[1] );
  }

  ver = eregmatch( pattern:'Firmware Version ?: V?([0-9.]+)', string:buf );
  if(ver[1])
  {
    ver = ver[1];
    set_kb_item( name:"dlink/dap/firmver", value:ver );
  }

  hwver = eregmatch( pattern:'>Hardware Version : ([0-9A-Za-z.]+)', string:buf );
  if(hwver[1]){
    set_kb_item( name:"dlink/dap/hwver", value:hwver[1] );
  }

  cpe = build_cpe(value:ver, exp:"^([0-9.]+)", base:"cpe:/h:dlink:dap:");
  if( isnull( cpe ) )
    cpe = 'cpe:/h:dlink:dap';

  register_product( cpe:cpe, location:'/', port:dlPort);
  log_message( data: build_detection_report( app: "D-Link DAP",
                                             version: ver,
                                             install: '/',
                                             cpe: cpe,
                                             concluded: ver),
                                             port: dlPort);

  exit (0);
}
exit (0);
