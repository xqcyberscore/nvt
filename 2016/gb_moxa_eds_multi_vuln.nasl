###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moxa_eds_multi_vuln.nasl 5588 2017-03-16 10:00:36Z teissa $
#
# Moxa EDS-405A/408A Multiple Vulnerabilities
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106107");
  script_version("$Revision: 5588 $");
  script_tag(name: "last_modification", value: "$Date: 2017-03-16 11:00:36 +0100 (Thu, 16 Mar 2017) $");
  script_tag(name: "creation_date", value: "2016-06-23 12:12:32 +0700 (Thu, 23 Jun 2016)");
  script_tag(name: "cvss_base", value: "8.5");
  script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:C/A:C");

  script_cve_id("CVE-2015-6464", "CVE-2015-6465", "CVE-2015-6466");

  script_tag(name: "qod_type", value: "remote_banner");

  script_tag(name: "solution_type", value: "VendorFix");

  script_name("Moxa EDS-405A/408A Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moxa_eds_detect.nasl");
  script_mandatory_keys("moxa_eds/detected");

  script_tag(name: "summary", value: "Moxa EDS-405A and EDS-408A is prone to multiple vulnerabilies");

  script_tag(name: "vuldetect", value: "Checks the version.");

  script_tag(name: "insight", value: "Moxa EDS-405A and EDS-408A is prone to multiple vulnerabilies:

The administrative web interface on Moxa EDS-405A and EDS-408A switches with firmware before 3.6 allows
remote authenticated users to bypass a read-only protection mechanism by using Firefox with a web-developer
plugin. (CVE-2015-6464)

The GoAhead web server on Moxa EDS-405A and EDS-408A switches with firmware before 3.6 allows remote
authenticated users to cause a denial of service (reboot) via a crafted URL. (CVE-2015-6465)

Cross-site scripting (XSS) vulnerability in the Diagnosis Ping feature in the administrative web interface
on Moxa EDS-405A and EDS-408A switches with firmware before 3.6 allows remote attackers to inject arbitrary
web script or HTML via an unspecified field. (CVE-2015-6466 (CVE-2015-6466 (CVE-2015-6466 (CVE-2015-6466 (CVE-2015-6466 (CVE-2015-6466 (CVE-2015-6466 (CVE-2015-6466 (CVE-2015-6466)");

  script_tag(name: "impact", value: "An authenticated attacker may bypass security restrictions or cause a
denial of service");

  script_tag(name: "affected", value: "Version prior to 3.6");

  script_tag(name: "solution", value: "Upgrade to Version 3.6 or later");

  script_xref(name: "URL", value: "http://www.moxa.com/support/download.aspx?type=support&id=328");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe1 = "cpe:/a:moxa:eds-405a";
cpe2 = "cpe:/a:moxa:eds-408a";

if (port = get_app_port(cpe: cpe1))
  model = cpe1;
else
  if (port = get_app_port(cpe: cpe2))
    model = cpe2;
  else
    exit(0);

if (!version = get_app_version(cpe: model, port: port))
  exit(0);

if (version_is_less(version: version ,test_version: "3.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.6");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
