###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_smh_mult_remote_vuln.nasl 7457 2017-10-17 10:18:09Z asteins $
#
# HP System Management Homepage Multiple Remote Vulnerabilities
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:hp:system_management_homepage";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112085");
  script_version("$Revision: 7457 $");
  script_tag(name: "last_modification", value: "$Date: 2017-10-17 12:18:09 +0200 (Tue, 17 Oct 2017) $");
  script_tag(name: "creation_date", value: "2017-10-17 12:34:56 +0200 (Tue, 17 Oct 2017)");
  script_tag(name: "cvss_base", value: "7.8");
  script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2016-8743", "CVE-2017-12544", "CVE-2017-12545", "CVE-2017-12546", "CVE-2017-12547",
      "CVE-2017-12548", "CVE-2017-12549", "CVE-2017-12550", "CVE-2017-12551", "CVE-2017-12552", "CVE-2017-12553");

  script_tag(name: "qod_type", value: "remote_banner");

  script_tag(name: "solution_type", value: "VendorFix");

  script_name("HP System Management Homepage Multiple Remote Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_hp_smh_detect.nasl");
  script_mandatory_keys("HP/SMH/installed");

  script_tag(name: "summary", value: "HP System Management Homepage is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect", value: "Checks the version.");

  script_tag(name: "insight", value: "Multiple potential security vulnerabilities have been identified in HPE
      System Management Homepage (SMH) on Windows and Linux.");

  script_tag(name: "impact", value: "The vulnerabilities could be exploited remotely resulting in Cross-site scripting,
      local and remote Denial of Service, local and remote execution of arbitrary code,
      local elevation of privilege and local unqualified configuration change.");

  script_tag(name: "affected", value: "HPE System Management Homepage all versions prior to v7.6.1");

  script_tag(name: "solution", value: "Update to v7.6.1 or later");

  script_xref(name: "URL", value: "https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbmu03753en_us");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "7.6.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.6.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
