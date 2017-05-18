###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpipam_xss_vuln.nasl 5746 2017-03-28 10:02:45Z ckuerste $
#
# phpipam Multiple XSS Vulnerabilities
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

CPE = "cpe:/a:ipam:ipam";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106700");
  script_version("$Revision: 5746 $");
  script_tag(name: "last_modification", value: "$Date: 2017-03-28 12:02:45 +0200 (Tue, 28 Mar 2017) $");
  script_tag(name: "creation_date", value: "2017-03-28 11:42:33 +0700 (Tue, 28 Mar 2017)");
  script_tag(name: "cvss_base", value: "4.3");
  script_tag(name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2017-6481");

  script_tag(name: "qod_type", value: "remote_banner");

  script_tag(name: "solution_type", value: "VendorFix");

  script_name("phpipam Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ipam_detect.nasl");
  script_mandatory_keys("ipam/installed");

  script_tag(name: "summary", value: "phpipam is prone to multiple cross-site scripting vulnerabilities.");

  script_tag(name: "vuldetect", value: "Checks the version.");

  script_tag(name: "insight", value: "The vulnerabilities exist due to insufficient filtration of user-supplied
data passed to several pages (instructions in app/admin/instructions/preview.php; subnetId in
app/admin/powerDNS/refresh-ptr-records.php).");

  script_tag(name: "impact", value: "An attacker could execute arbitrary HTML and script code in a browser in the
context of the vulnerable website.");

  script_tag(name: "affected", value: "phpipam 1.2.1 and prior.");

  script_tag(name: "solution", value: "Apply the provided patch.");

  script_xref(name: "URL", value: "https://github.com/phpipam/phpipam/issues/992");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "1.2.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Apply patch.");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
