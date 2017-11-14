###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dotcms_xss_vuln.nasl 7676 2017-11-07 08:01:38Z asteins $
#
# dotCMS Multiple XSS Vulnerabilities
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

CPE = "cpe:/a:dotcms:dotcms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106572");
  script_version("$Revision: 7676 $");
  script_tag(name: "last_modification", value: "$Date: 2017-11-07 09:01:38 +0100 (Tue, 07 Nov 2017) $");
  script_tag(name: "creation_date", value: "2017-02-07 11:43:11 +0700 (Tue, 07 Feb 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2017-5876", "CVE-2017-5875", "CVE-2017-5877", "CVE-2017-6003");

  script_tag(name: "qod_type", value: "remote_banner");

  script_tag(name: "solution_type", value: "NoneAvailable");

  script_name("dotCMS Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dotcms_detect.nasl");
  script_mandatory_keys("dotCMS/installed");

  script_tag(name: "summary", value: "dotCMS is prone to multiple cross-site scripting vulnerabilities.");

  script_tag(name: "vuldetect", value: "Checks the version.");

  script_tag(name: "insight", value: "dotCMS is prone to multiple cross-site scripting vulnerabilities:

- XSS with an authenticated attack against the /myAccount addressID parameter. (CVE-2017-5875)

- XSS with an unauthenticated attack against the /news-events/events date parameter. (CVE-2017-5876)

- XSS with an unauthenticated attack against the /about-us/locations/index direction parameter. (CVE-2017-5877)");

  script_tag(name: "affected", value: "Version 3.7.0 and previous versions.");

  script_tag(name: "solution", value: "No solution or patch is available as of 7th November, 2017. Information
regarding this issue will be updated once the solution details are available.");

  script_xref(name: "URL", value: "https://github.com/dotCMS/core/issues/10643");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "3.7.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
