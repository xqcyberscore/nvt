###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vimbadmin_mult_vuln.nasl 7613 2017-11-01 14:51:05Z asteins $
#
# ViMbAdmin Multiple Vulnerabilities
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

CPE = "cpe:/a:vimbadmin:vimbadmin";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106872");
  script_version("$Revision: 7613 $");
  script_tag(name: "last_modification", value: "$Date: 2017-11-01 15:51:05 +0100 (Wed, 01 Nov 2017) $");
  script_tag(name: "creation_date", value: "2017-06-14 11:20:52 +0700 (Wed, 14 Jun 2017)");
  script_tag(name: "cvss_base", value: "6.8");
  script_tag(name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-5870", "CVE-2017-6086");

  script_tag(name: "qod_type", value: "remote_banner");

  script_tag(name: "solution_type", value: "NoneAvailable");

  script_name("ViMbAdmin Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_vimbadmin_detect.nasl");
  script_mandatory_keys("vimbadmin/installed");

  script_tag(name: "summary", value: "ViMbAdmin is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect", value: "Checks the version.");

  script_tag(name: "insight", value: "ViMbAdmin is prone to multiple vulnerabilities:

- Multiple XSS vulnerabilities (CVE-2017-5870)

- Multiple CSRF vulnerabilities (CVE-2017-6086)");

  script_tag(name: "affected", value: "ViMbAdmin version 3.0.15 and prior.");

  script_tag(name: "solution", value: "No solution or patch is available as of 01st November, 2017. Information
regarding this issue will be updated once the solution details are available.");

  script_xref(name: "URL", value: "https://sysdream.com/news/lab/2017-05-03-cve-2017-5870-multiple-xss-vulnerabilities-in-vimbadmin/");
  script_xref(name: "URL", value: "https://sysdream.com/news/lab/2017-05-03-cve-2017-6086-multiple-csrf-vulnerabilities-in-vimbadmin-version-3-0-15/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "3.0.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
