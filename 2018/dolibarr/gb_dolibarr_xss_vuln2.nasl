###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dolibarr_xss_vuln2.nasl 8757 2018-02-12 08:44:48Z asteins $
#
# Dolibarr XSS Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

CPE = "cpe:/a:dolibarr:dolibarr";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112215");
  script_version("$Revision: 8757 $");
  script_tag(name: "last_modification", value: "$Date: 2018-02-12 09:44:48 +0100 (Mon, 12 Feb 2018) $");
  script_tag(name: "creation_date", value: "2018-02-12 09:37:40 +0100 (Mon, 12 Feb 2018)");
  script_tag(name: "cvss_base", value: "4.3");
  script_tag(name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2017-1000509");

  script_tag(name: "qod_type", value: "remote_banner");

  script_tag(name: "solution_type", value: "NoneAvailable");

  script_name("Dolibarr XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dolibarr_detect.nasl");
  script_mandatory_keys("Dolibarr/installed");

  script_tag(name: "summary", value: "Dolibarr ERP/CRM is prone to a cross-site scripting vulnerability.");

  script_tag(name: "vuldetect", value: "Checks the version.");

  script_tag(name: "insight", value: "Cross Site Scripting (XSS) exists in product details that can result in execution of javascript code.
The payload is saved with no interference from the detector. When visiting the page later, the payload executes.");

  script_tag(name: "affected", value: "Dolibarr ERP/CRM version 6.0.2.");

  script_tag(name: "solution", value: "No solution or patch is available as of 12th February, 2018. Information
regarding this issue will be updated once the solution details are available.");

  script_xref(name: "URL", value: "https://github.com/Dolibarr/dolibarr/issues/7727");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "6.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
