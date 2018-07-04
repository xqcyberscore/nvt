###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_open_xchange_appsuite_mult_vuln_july18.nasl 10383 2018-07-03 13:42:14Z ckuersteiner $
#
# Open-Xchange (OX) AppSuite Multiple Vulnerabilities (July18)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/a:open-xchange:open-xchange_appsuite";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141264");
  script_version("$Revision: 10383 $");
  script_tag(name: "last_modification", value: "$Date: 2018-07-03 15:42:14 +0200 (Tue, 03 Jul 2018) $");
  script_tag(name: "creation_date", value: "2018-07-03 14:31:36 +0200 (Tue, 03 Jul 2018)");
  script_tag(name: "cvss_base", value: "6.4");
  script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2018-9997", "CVE-2018-9998");

  script_tag(name: "qod_type", value: "remote_banner");

  script_tag(name: "solution_type", value: "VendorFix");

  script_name("Open-Xchange (OX) AppSuite Multiple Vulnerabilities (July18)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ox_app_suite_detect.nasl");
  script_mandatory_keys("open_xchange_appsuite/installed");

  script_tag(name: "summary", value: "Open-Xchange AppSuite is prone to multiple vulnerabilities.");

  script_tag(name: "insight", value: "Open-Xchange AppSuite is prone to multiple vulnerabilities:

- XXE vulnerability

- Multiple XSS vulnerabilities (CVE-2018-9997)

- Information Exposure (CVE-2018-9998)");

  script_tag(name: "vuldetect", value: "Checks the version.");

  script_tag(name: "solution", value: "Update to version 7.6.3-rev31, 7.8.2-rev31, 7.8.3-rev41, 7.8.4-rev28 or
later.");

  script_xref(name: "URL", value: "http://seclists.org/fulldisclosure/2018/Jul/12");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE);
version = infos['version'];
path = infos['location'];

revision = get_kb_item("open_xchange_appsuite/" + port + "/revision");
if (!revision)
  exit(0);

version += "." + revision;

if (version_is_less(version: version, test_version: "7.6.3.31")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.6.3.31");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.7", test_version2: "7.8.2.30")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.8.2.31");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.8.3", test_version2: "7.8.3.40")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.8.3.41");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.8.4", test_version2: "7.8.4.27")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.8.4.28");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
