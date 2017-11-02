###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openemr_xss_vuln.nasl 7610 2017-11-01 13:14:39Z jschulte $
#
# OpenEMR Multiple XSS Vulnerabilities
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

CPE = "cpe:/a:open-emr:openemr";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106635");
  script_version("$Revision: 7610 $");
  script_tag(name: "last_modification", value: "$Date: 2017-11-01 14:14:39 +0100 (Wed, 01 Nov 2017) $");
  script_tag(name: "creation_date", value: "2017-03-07 08:12:26 +0700 (Tue, 07 Mar 2017)");
  script_tag(name: "cvss_base", value: "4.3");
  script_tag(name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2017-6394", "CVE-2017-6482");
  script_bugtraq_id(96539);

  script_tag(name: "qod_type", value: "remote_banner");

  script_tag(name: "solution_type", value: "NoneAvailable");

  script_name("OpenEMR Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_openemr_detect.nasl");
  script_mandatory_keys("openemr/installed");

  script_tag(name: "summary", value: "OpenEMR is prone to multiple cross-site scripting vulnerabilities.");

  script_tag(name: "vuldetect", value: "Checks the version.");

  script_tag(name: "insight", value: "The vulnerability exists due to insufficient filtration of user-supplied
data in multiple HTTP GET parameters passed to 'openemr-master/gacl/admin/object_search.php' url.");

  script_tag(name: "impact", value: "An attacker could execute arbitrary HTML and script code in browser in
context of the vulnerable website.");

  script_tag(name: "affected", value: "OpenEMR 5.0.1-dev and prior.");

  script_tag(name: "solution", value: "No solution or patch is available as of 1st November, 2017. Information
regarding this issue will be updated once the solution details are available.");


  script_xref(name: "URL", value: "https://github.com/openemr/openemr/issues/498");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "5.0.1-dev")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
