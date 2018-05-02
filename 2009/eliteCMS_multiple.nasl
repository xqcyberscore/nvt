###############################################################################
# OpenVAS Vulnerability Test
# $Id: eliteCMS_multiple.nasl 9678 2018-04-30 10:01:10Z ckuersteiner $
#
# eliteCMS Multiple Vulnerabilities
#
# Authors
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:elitecms:elitecms";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100222");
 script_version("$Revision: 9678 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-30 12:01:10 +0200 (Mon, 30 Apr 2018) $");
 script_tag(name:"creation_date", value:"2009-06-14 17:19:03 +0200 (Sun, 14 Jun 2009)");
 script_bugtraq_id(35155,30990);
 script_cve_id("CVE-2008-4046");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_tag(name: "solution_type", value: "WillNotFix");

 script_name("eliteCMS Multiple Vulnerabilities");

 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_active");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("eliteCMS_detect.nasl");
 script_mandatory_keys("elitecms/installed");

 script_tag(name: "summary", value: "eliteCMS is prone to a vulnerability that lets attackers upload and execute
arbitrary PHP code. The application is also prone to a cross-site scripting issue and to a SQL Injection
Vulnerability. These issues occur because the application fails to sufficiently sanitize user-supplied input.

Attackers can exploit these issues to steal cookie information, execute arbitrary client-side scripts in the
context of the browser, upload and execute arbitrary files in the context of the webserver, compromise the
application, access or modify data, exploit latent vulnerabilities in the underlying database and launch other
attacks.

These issues affect eliteCMS 1.01, other versions may also be affected.");

 script_tag(name: "solution", value: "No solution or patch was made available for at least one year since
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
to a newer release, disable respective features, remove the product or replace the product by another one.");

 script_xref(name: "URL", value: "http://xforce.iss.net/xforce/xfdb/50869");
 script_xref(name: "URL", value: "http://www.securityfocus.com/bid/35155");
 script_xref(name: "URL", value: "http://www.securityfocus.com/bid/30990");

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

url = dir + "/index.php?page=-1%27";

if (http_vuln_check(port: port, url: url, pattern: "You have an error in your SQL", check_header: TRUE)) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
