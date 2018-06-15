###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_brother_hl_series_printer_detect.nasl 10182 2018-06-14 07:00:55Z santu $
#
# Brother HL Series Printers Detection 
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.813390");
  script_version("$Revision: 10182 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-06-14 09:00:55 +0200 (Thu, 14 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-06-06 15:18:41 +0530 (Wed, 06 Jun 2018)");
  script_name("Brother HL Series Printers Detection");

  script_tag(name:"summary", value:"Detection of installed version of
  Brother HL Series Printer.

  The script sends a connection request to the server and attempts to extract
  the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!brPort = get_http_port(default:80)){
  exit(0);
}

res = http_get_cache(item:"/general/information.html?kind=item", port:brPort);

if(res =~ "<title>Brother HL.*series</title>" && res =~ "Copyright.*Brother Industries") 
{
  version = "unknown";
  model = "unknown";

  set_kb_item( name:"Brother/HL/Printer/installed", value:TRUE );

  model = eregmatch(pattern:'modelName"><h1>([0-9A-Z-]+) series</h1>', string:res);
  ver = eregmatch(pattern:"Firmware&#32;Version</dt><dd>([0-9.]+)</dd>", string:res);
  
  if(model[1])
  {
    model = model[1];
    set_kb_item(name:"Brother/HL/Printer/model", value:model);
  }
  if(ver[1])
  {
    version = ver[1];
    set_kb_item(name:"Brother/HL/Printer/version", value:version);
  }

  cpe = build_cpe(value:version, exp:"^([0-9.]+)", base: "cpe:/h:brother:" + tolower(model) + ":");
  if(!cpe)
    cpe = 'cpe:/h:brother:' + tolower(model);

  register_product( cpe:cpe, port:brPort, location:"/");
  log_message( data:build_detection_report( app:"Brother HL series printer",
                                            version:version,
                                            install:"/",
                                            cpe:cpe,
                                            concluded:model + " Firmware " + version),
                                            port:brPort );
  exit(0);
}
exit(0);
