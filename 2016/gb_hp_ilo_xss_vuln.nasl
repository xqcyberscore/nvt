###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_ilo_xss_vuln.nasl 4800 2016-12-19 10:54:55Z ckuerste $
#
# HP Integrated Lights-Out XSS Vulnerability
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

CPE = "cpe:/o:hp:integrated_lights-out";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106481");
  script_version("$Revision: 4800 $");
  script_tag(name: "last_modification", value: "$Date: 2016-12-19 11:54:55 +0100 (Mon, 19 Dec 2016) $");
  script_tag(name: "creation_date", value: "2016-12-19 15:31:29 +0700 (Mon, 19 Dec 2016)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2016-4406");

  script_tag(name: "qod_type", value: "remote_banner");

  script_tag(name: "solution_type", value: "VendorFix");

  script_name("HP Integrated Lights-Out XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("ilo_detect.nasl");
  script_mandatory_keys("HP_ILO/installed");

  script_tag(name: "summary", value: "HP Integrated Lights-Out is prone to a cross-site scripting vulnerability.");

  script_tag(name: "vuldetect", value: "Checks the version.");

  script_tag(name: "affected", value: "HPE Integrated Lights-Out 3 (iLO 3) and HPE Integrated Lights-Out 4
(iLO 4)");

  script_tag(name: "solution", value: "Upgrade to firmware 1.88 (iLO 3), 2.44 (iLO 4)");

  script_xref(name: "URL", value: "https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05337025");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (!ilo_version = get_kb_item('www/' + port + '/HP_ILO/ilo_version'))
  exit(0);

if (ilo_version == 3) {
  if (version_is_less(version: version, test_version: "1.88")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.88");
    security_message(port: port, data: report);
  }
  exit(0);
}

if (ilo_version == 4) {
  if (version_is_less(version: version, test_version: "2.44")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.44");
    security_message(port: port, data: report);
  }
  exit(0);
}

exit(0);
