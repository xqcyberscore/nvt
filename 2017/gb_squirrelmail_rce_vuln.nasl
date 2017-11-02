###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_squirrelmail_rce_vuln.nasl 7613 2017-11-01 14:51:05Z asteins $
#
# SquirrelMail Remote Code Execution Vulnerability
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

CPE = 'cpe:/a:squirrelmail:squirrelmail';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106785");
  script_version("$Revision: 7613 $");
  script_tag(name: "last_modification", value: "$Date: 2017-11-01 15:51:05 +0100 (Wed, 01 Nov 2017) $");
  script_tag(name: "creation_date", value: "2017-04-21 17:09:27 +0200 (Fri, 21 Apr 2017)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2017-7692");

  script_tag(name: "qod_type", value: "remote_banner");

  script_tag(name: "solution_type", value: "NoneAvailable");

  script_name("SquirrelMail Remote Code Execution Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("squirrelmail_detect.nasl");
  script_mandatory_keys("squirrelmail/installed");

  script_tag(name: "summary", value: "SquirrelMail is prone to an authenticated remote code execution
vulnerability.");

  script_tag(name: "vuldetect", value: "Checks the version.");

  script_tag(name: "insight", value: "SquirrelMail allows post-authentication remote code execution via a
sendmail.cf file that is mishandled in a popen call. It's possible to exploit this vulnerability to execute
arbitrary shell commands on the remote server.");

  script_tag(name: "impact", value: "An authenticated attacker may execute arbitrary shell commands.");

  script_tag(name: "affected", value: "SquirrelMail 1.4.22 and prior as well as the trunk version.");

  script_tag(name: "solution", value: "No solution or patch is available as of 01st November, 2017. Information
regarding this issue will be updated once the solution details are available.");

  script_xref(name: "URL", value: "https://www.wearesegment.com/research/Squirrelmail-Remote-Code-Execution.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

# trunk is currently 1.4.23 which is as well vulnerable
if (version_is_less_equal(version: version, test_version: "1.4.23")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See reference");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
