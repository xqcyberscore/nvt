##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_simatic_s7_mult_vuln.nasl 4772 2016-12-15 09:55:20Z ckuerste $
#
# Siemens SIMATIC S7-300/400 PLC Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.106476");
  script_version("$Revision: 4772 $");
  script_tag(name: "last_modification", value: "$Date: 2016-12-15 10:55:20 +0100 (Thu, 15 Dec 2016) $");
  script_tag(name: "creation_date", value: "2016-12-15 10:22:34 +0700 (Thu, 15 Dec 2016)");
  script_tag(name: "cvss_base", value: "7.8");
  script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2016-9158", "CVE-2016-9159");

  script_tag(name: "qod_type", value: "remote_banner_unreliable");

  script_tag(name: "solution_type", value: "Mitigation");

  script_name("Siemens SIMATIC S7-300/400 PLC Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_simatic_s7_version.nasl");
  script_mandatory_keys("simatic_s7/detected");

  script_tag(name: "summary", value: "Siemens SIMATIC S7-300 and S7-400 are prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect", value: "Checks if a HTTP port or the COTP port is open.");

  script_tag(name: "insight", value: "Siemens SIMATIC S7-300 and S7-400 are prone to multiple vulnerabilities:

- Specially crafted packets sent to Port 80/TCP could cause the affected devices to go into defect mode.
(CVE-2016-9158)

- An attacker with network access to Port 102/TCP (ISO-TSAP) could obtain credentials from the PLC if
Protection-level 2 is configured on the affected devices. (CVE-2016-9159)");

  script_tag(name: "impact", value: "A remote attacker may cause a DoS condition or obtain credentials.");

  script_tag(name: "affected", value: "All versions.");

  script_tag(name: "solution", value: "Siemens recommends the following mitigations:

- Deactivate the web server

- Apply protection-level 3

- Apply cell protection concept

- Use VPN for protecting network communication between cells");

  script_xref(name: "URL", value: "https://ics-cert.us-cert.gov/advisories/ICSA-16-348-05");
  script_xref(name: "URL", value: "https://www.siemens.com/cert/pool/cert/siemens_security_advisory_ssa-731239.pdf");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

model = get_kb_item("simatic_s7/model");

if (model !~ "^(3|4)00")
  exit(0);

cotp = get_kb_item("simatic_s7/cotp/port");
http = get_kb_item("simatic_s7/http/port");

if (cotp || http) {
  security_message(port: port);
  exit(0);
}

exit(0);

