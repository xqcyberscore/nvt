###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zenbership_cms_detect.nasl 8139 2017-12-15 11:57:25Z cfischer $
#
# Zenbership CMS Detection
#
# Authors:
# Tameem Eissa <tameem.eissa..at..greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.107220");
  script_version("$Revision: 8139 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-15 12:57:25 +0100 (Fri, 15 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-06-12 06:40:16 +0200 (Mon, 12 Jun 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Zenbership CMS Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of installed version of Zenbership CMS

  The script detects the version of Zenbership CMS remote host and sets the KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

appPort = get_http_port(default: 80);

foreach dir(make_list_unique( "/", cgi_dirs( port: appPort ) ) ) {

  install = dir;
  if (dir == "/") dir = "";

  url = dir +  "/admin/login.php";

  rcvRes = http_get_cache(item: url, port: appPort);

  if (rcvRes !~ "^HTTP/1\.[01] 200" || "<title>Welcome to Zenbership" >!< rcvRes || "Zenbership Membership Software" >!< rcvRes) continue;

  Ver = 'unknown';

  tmpVer = eregmatch(pattern: ">v([0-9a-z]+)",
                     string: rcvRes);

  if(tmpVer[1]) {
    Ver = tmpVer[1];
  }

  set_kb_item(name: "zenbership/installed", value: TRUE);
  set_kb_item(name: "zenbership/version", value: Ver);

  cpe = build_cpe(value: Ver, exp: "^([0-9a-z]+)", base: "cpe:/a:castlamp:zenbership:");

  if(!cpe)
    cpe = 'cpe:/a:castlamp:zenbership';

  register_product(cpe: cpe, location: install, port: appPort);

  log_message(data:build_detection_report(app: "Zenbership",
                                          version: Ver,
                                          install: install,
                                          cpe: cpe,
                                          concluded: tmpVer[0]),
                                          port: appPort);
}

exit(0);
