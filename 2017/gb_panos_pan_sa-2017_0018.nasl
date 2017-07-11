###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_panos_pan_sa-2017_0018.nasl 6374 2017-06-20 02:46:53Z ckuersteiner $
#
# Palo Alto PAN-OS Kernel Vulnerability
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

CPE = 'cpe:/o:altaware:palo_alto_networks_panos';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106882");
  script_version("$Revision: 6374 $");
  script_tag(name: "last_modification", value: "$Date: 2017-06-20 04:46:53 +0200 (Tue, 20 Jun 2017) $");
  script_tag(name: "creation_date", value: "2017-06-20 09:10:58 +0700 (Tue, 20 Jun 2017)");
  script_tag(name: "cvss_base", value: "10.0");
  script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2016-10229");

  script_tag(name: "qod_type", value: "package");

  script_tag(name: "solution_type", value: "VendorFix");

  script_name("Palo Alto PAN-OS Kernel Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_palo_alto_panOS_version.nasl");
  script_mandatory_keys("palo_alto_pan_os/version");

  script_tag(name: "summary", value: "A vulnerability exists in the Linux kernel of PAN-OS that may result in
Remote Code Execution.");

  script_tag(name: "vuldetect", value: "Checks the version.");

  script_tag(name: "insight", value: "A vulnerability in the Linux kernel networking subsystem for UDP could
enable an attacker to execute arbitrary code within the context of the kernel. The Data Plane (DP) of PAN-OS is
not affected by this issue since it does not use the vulnerable Linux kernel code.");

  script_tag(name: "affected", value: "PAN-OS 6.1, PAN-OS 7.0, PAN-OS 7.1, PAN-OS 8.0.2 and earlier.");

  script_tag(name: "solution", value: "Update to PAN-OS 8.0.3 and later.");

  script_xref(name: "URL", value: "https://securityadvisories.paloaltonetworks.com/Home/Detail/88");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

model = get_kb_item("palo_alto_pan_os/model");

if (version_is_less(version: version, test_version: "8.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.3");

  if (model)
    report += '\nModel:             ' + model;

  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
