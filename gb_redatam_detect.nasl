###############################################################################
# OpenVAS Vulnerability Test
#
# Redatam Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.141196");
  script_version("2019-07-26T10:54:19+0000");
  script_tag(name:"last_modification", value:"2019-07-26 10:54:19 +0000 (Fri, 26 Jul 2019)");
  script_tag(name:"creation_date", value:"2018-06-19 13:09:25 +0700 (Tue, 19 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Redatam Detection");

  script_tag(name:"summary", value:"Detection of Redatam.

  The script sends a connection request to the server and attempts to detect Redatam.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_keys("Host/runs_windows");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://redatam.org/redatam/en/index.html");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

url = "/redbin/RpWebUtilities.exe";
res = http_get_cache(port: port, item: url );

# <h1>Redatam WebUtilities Default Action</h1>
# <h1>R+SP WebUtilities Default Action</h1>
if (res =~ "^HTTP/1\.[01] 200" && egrep(string: res, pattern: "<h1>(R\+SP|Redatam) WebUtilities Default Action</h1>", icase: FALSE)) {
  version = "unknown";
  conclUrl = report_vuln_url(url: url, port: port, url_only: TRUE);

  set_kb_item(name: "redatam/installed", value: TRUE);

  cpe = "cpe:/a:redatam:redatam";

  register_product(cpe: cpe, location: "/redbin", port: port, service: "www");

  log_message(data: build_detection_report(app: "Redatam", version: version, install: "/redbin", cpe: cpe, concludedUrl: conclUrl),
              port: port);
}

exit(0);
