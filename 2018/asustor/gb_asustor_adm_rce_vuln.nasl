##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_asustor_adm_rce_vuln.nasl 10372 2018-06-29 14:44:40Z ckuersteiner $
#
# ASUSTOR ADM RCE Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/h:asustor:adm_firmware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141251");
  script_version("$Revision: 10372 $");
  script_tag(name: "last_modification", value: "$Date: 2018-06-29 16:44:40 +0200 (Fri, 29 Jun 2018) $");
  script_tag(name: "creation_date", value: "2018-06-29 14:18:00 +0200 (Fri, 29 Jun 2018)");
  script_tag(name: "cvss_base", value: "10.0");
  script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2018-11510");

  script_tag(name: "qod_type", value: "remote_banner");

  script_tag(name: "solution_type", value: "VendorFix");

  script_name("ASUSTOR ADM RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_asustor_adm_detect.nasl");
  script_mandatory_keys("asustor_adm/detected");

  script_tag(name: "summary", value: "A remote command injection vulnerability exists in ASUSTOR ADM. Successful
exploitation would allow an attacker to execute arbitrary code on the target machine.");

  script_tag(name: "vuldetect", value: "Checks the version.");

  script_tag(name: "affected", value: "ASUSTOR ADM 3.1.2.RHG1 and prior.");

  script_tag(name: "solution", value: "Update to the latest version.");

  script_xref(name: "URL", value: "https://github.com/mefulton/CVE-2018-11510");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "3.1.2.rhg1")) {
  report = report_fixed_ver(installed_version: toupper(version), fixed_version: "Contact vendor");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
