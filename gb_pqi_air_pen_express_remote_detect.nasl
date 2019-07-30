###############################################################################
# OpenVAS Vulnerability Test
#
# PQI Air Pen Express Remote Detection
#
# Authors:
# Rinu Kuriaksoe <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.807535");
  script_version("2019-07-29T09:50:23+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-07-29 09:50:23 +0000 (Mon, 29 Jul 2019)");
  script_tag(name:"creation_date", value:"2016-02-18 10:58:19 +0530 (Thu, 18 Feb 2016)");
  script_name("PQI Air Pen Express Remote Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of installed version
  of PQI Air Pen Express.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port(default:80);
if(!can_host_asp(port:port))
  exit(0);

res = http_get_cache(item:"/home.asp", port:port);

if(res && '<TITLE>Air Pen express' >< res) {

  install = "/";
  version = "unknown";

  set_kb_item(name:"pqi/air_pen_express/detected", value:TRUE);

  cpe = "cpe:/a:pqi:air_pen_express";

  register_product(cpe:cpe, location:install, port:port, service:"www");

  log_message(data:build_detection_report(app:"PQI Air Pen Express",
                                          version:version,
                                          install:install,
                                          cpe:cpe),
                                          port:port);
}

exit(0);
