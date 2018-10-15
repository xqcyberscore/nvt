###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_atlassian_crowd_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Atlassian Crowd Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106374");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-11-04 14:37:33 +0700 (Fri, 04 Nov 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Atlassian Crowd Detection");

  script_tag(name:"summary", value:"Detection of Atlassian Crowd

The script sends a connection request to the server and attempts to detect the presence of Atlassian Crowd and to
extract its version");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.atlassian.com/software/crowd");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

req = http_get(port: port, item: "/crowd/console/login.action");
res = http_keepalive_send_recv(port: port, data: req);

if ("<title>Atlassian Crowd - Login" >< res && "/crowd/console/j_security_check" >< res) {
  version = "unknown";

  vers = eregmatch(pattern: "Version:&nbsp;([0-9.]+)", string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "atlassian_crowd/version", value: version);
  }

  set_kb_item(name: "atlassian_crowd/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:atlassian:crowd:");
  if (!cpe)
    cpe = 'cpe:/a:atlassian:crowd';

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "Atlassian Crowd", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
