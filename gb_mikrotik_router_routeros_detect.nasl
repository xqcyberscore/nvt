###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mikrotik_router_routeros_detect.nasl 5829 2017-04-03 07:00:29Z cfi $
#
# MikroTik Router RouterOS (OS Of RouterBOARD) Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.810608");
  script_version("$Revision: 5829 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-04-03 09:00:29 +0200 (Mon, 03 Apr 2017) $");
  script_tag(name:"creation_date", value:"2017-03-09 15:28:48 +0530 (Thu, 09 Mar 2017)");
  script_name("MikroTik Router RouterOS (OS Of RouterBOARD) Detection");

  script_tag(name:"summary", value:"Detection of MikroTik Router RouterOS.

  The script sends a connection request to the server and attempts to
  detect the presence of MikroTik Router.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 10000);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

##Variable Initialization
mikPort = "";
req = "";
res = "";
mikVer = "";

mikPort = get_http_port(default: 10000);

res = http_get_cache(port:mikPort, item: "/");

##Confirm Router
if(">RouterOS router configuration page<" >< res && "mikrotik<" >< res && ">Login<" >< res)
{
  mikVer = 'unknown';

  set_kb_item(name:"mikrotik/detected", value: TRUE);

  vers = eregmatch(pattern: ">RouterOS v([0-9.]+)<", string: res);
  if(vers[1])
  {
    mikVer = vers[1];
    set_kb_item(name: "mikrotik/routeros/version", value: mikVer);
  }

  ## No cpe name available, assigning CPE = cpe:/a:mikrotik:routeros
  cpe = build_cpe(value: mikVer, exp: "^([0-9.]+)", base: "cpe:/a:mikrotik:routeros:");
  if (!cpe)
    cpe = "cpe:/a:mikrotik:routeros";

  register_product(cpe: cpe, location: "/", port: mikPort);

  log_message(data: build_detection_report(app: "Mikrotik RouterOS",
                                           version: mikVer,
                                           install: "/",
                                           cpe: cpe,
                                           concluded: mikVer),
                                           port: mikPort);
  exit(0);
}
exit(0);
