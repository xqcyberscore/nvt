###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sap_netweaver_sql_inj_vuln.nasl 5689 2017-03-23 10:00:49Z teissa $
#
# SAP NetWeaver Multiple Vulnerabilities
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

CPE = 'cpe:/a:sap:netweaver';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106083");
  script_version("$Revision: 5689 $");
  script_tag(name: "last_modification", value: "$Date: 2017-03-23 11:00:49 +0100 (Thu, 23 Mar 2017) $");
  script_tag(name: "creation_date", value: "2016-05-23 10:42:10 +0700 (Mon, 23 May 2016)");
  script_tag(name: "cvss_base", value: "7.5");
  script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2016-2386", "CVE-2016-2388");

  script_tag(name: "qod_type", value: "remote_banner_unreliable");

  script_tag(name: "solution_type", value: "VendorFix");

  script_name("SAP NetWeaver Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_sap_netweaver_detect.nasl");
  script_mandatory_keys("sap_netweaver/installed");

  script_tag(name: "summary", value: "SAP NetWeaver is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect", value: "Checks the version.");

  script_tag(name: "insight", value: "SQL injection vulnerability in the UDDI server (CVE-2016-2386).
The Universal Worklist Configuration in SAP NetWeaver 7.4 allows remote attackers to obtain sensitive
user information via a crafted HTTP request (CVE-2016-2388).");

  script_tag(name: "impact", value: "A remote attacker may execute arbitrary SQL commands or obtain
sensitive user information via a crafted HTTP request.");

  script_tag(name: "affected", value: "Version 7.1 until 7.5");

  script_tag(name: "solution", value: "Check the references for solutions ");

  script_xref(name: "URL", value: "https://service.sap.com/sap/support/notes/2101079");
  script_xref(name: "URL", value: "https://service.sap.com/sap/support/notes/2256846");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE))
  exit(0);

if (version_in_range(version: version, test_version: "7.10", test_version2: "7.50")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory.");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
