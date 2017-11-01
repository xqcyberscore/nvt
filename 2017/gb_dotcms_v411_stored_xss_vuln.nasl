###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dotcms_v411_stored_xss_vuln.nasl 7604 2017-11-01 06:48:12Z asteins $
#
# dotCMS 4.1.1 Stored Cross-Site Scripting (XSS) Vulnerability
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

CPE = "cpe:/a:dotcms:dotcms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112090");
  script_version("$Revision: 7604 $");
  script_tag(name: "last_modification", value: "$Date: 2017-11-01 07:48:12 +0100 (Wed, 01 Nov 2017) $");
  script_tag(name: "creation_date", value: "2017-10-20 11:47:18 +0200 (Fri, 20 Oct 2017)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2017-15219");

  script_tag(name: "qod_type", value: "remote_banner");

  script_tag(name: "solution_type", value: "NoneAvailable");

  script_name("dotCMS 4.1.1 Stored Cross-Site Scripting (XSS) Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dotcms_detect.nasl");
  script_mandatory_keys("dotCMS/installed");

  script_tag(name: "summary", value: "dotCMS version 4.1.1 is prone to a stored cross-site scripting (XSS) vulnerability.");

  script_tag(name: "vuldetect", value: "Checks the version.");

  script_tag(name: "insight", value: "dotCMS is vulnerable to stored XSS within multiple sections of the application.
      The application does not sanitize user supplied input and renders injected javascript code to the users browsers.");

  script_tag(name: "impact", value: "Attackers use this vulnerability to inject malicious javascript code such as a malicious redirect,
      crypto currency mining, or exploit kit.");

  script_tag(name: "affected", value: "dotCMS version 4.1.1.");

  script_tag(name: "solution", value: "No solution or patch is available as of 20th October, 2017.
      Information regarding this issue will be updated once the solution details are available.");

  script_xref(name: "URL", value: "https://raw.githubusercontent.com/badbiddy/Vulnerability-Disclosure/master/dotCMS%20%3E%204.1.1%20-%20Stored%20XSS");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_equal(version: version, test_version: "4.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "NoneAvailable");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
