###############################################################################
# OpenVAS Vulnerability Test
#
# ManageEngine Applications Manager Detection
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.808054");
  script_version("2019-08-20T08:12:54+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-08-20 08:12:54 +0000 (Tue, 20 Aug 2019)");
  script_tag(name:"creation_date", value:"2016-05-23 10:45:33 +0530 (Mon, 23 May 2016)");

  script_name("ManageEngine Applications Manager Detection");

  script_tag(name:"summary", value:"Detection of ManageEngine Applications Manager

  The script sends a connection request to the server and attempts to detect ManageEngine Applications Manager
  and to extract its version.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_require_ports("Services/www", 9090, 8443);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

managePort = get_http_port(default:9090);

foreach dir (make_list_unique( "/", "/manageengine", cgi_dirs(port:managePort))) {
  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/index.do";

  rcvRes = http_get_cache(port: managePort, item: url);

  if ("manageengine" >< rcvRes && '<title>Applications Manager Login Screen</title>' >< rcvRes) {
    version = "unknown";

    vers = eregmatch(pattern: "\?build=([0-9]+)", string: rcvRes);
    if (!isnull(vers[1])) {
      version = vers[1];
    } else {
      # Applications Manager (Build No:14260)
      vers = eregmatch(pattern: "Build No:([0-9]+)", string: rcvRes);
      if (!isnull(vers[1]))
        version = vers[1];
    }

    set_kb_item(name: "ManageEngine/Applications/Manager/Installed", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9]+)", base: "cpe:/a:manageengine:applications_manager:");
    if (!cpe)
      cpe = "cpe:/a:manageengine:applications_manager";

    register_product(cpe:cpe, location:install, port:managePort);

    log_message(data:build_detection_report(app: "ManageEngine Applications Manager", version: version,
                                            install: install, cpe: cpe, concluded: vers[0]),
                port:managePort);
    exit(0);
  }
}

exit(0);
