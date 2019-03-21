###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tenable_nessus_mult_vuln_tns-2018-16.nasl 13699 2019-02-15 14:29:50Z cfischer $
#
# Tenable Nessus < 8.1.1 Multiple Vulnerabilities (tns-2018-16)
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:tenable:nessus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107443");
  script_version("$Revision: 13699 $");
  script_cve_id("CVE-2018-0734", "CVE-2018-5407");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 15:29:50 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-01-09 12:18:54 +0100 (Wed, 09 Jan 2019)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Tenable Nessus < 8.1.1 Multiple Vulnerabilities (tns-2018-16)");

  script_tag(name:"summary", value:"This host is running Nessus and is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Tenable Nessus is affected by multiple vulnerabilities:

  - Tenable Nessus contains a flaw in the bundled third-party component OpenSSL library's DSA signature algorithm that renders it vulnerable to a timing side channel attack.

  - Tenable Nessus contains a flaw in the bundled third-party component OpenSSL library's Simultaneous Multithreading (SMT) architectures which render it vulnerable to side-channel leakage. This issue is known as 'PortSmash'.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers potentially to recover the private key. They could possibly use this issue to perform a timing side-channel attack and recover private keys.");

  script_tag(name:"affected", value:"Nessus versions prior to version 8.1.1.");

  script_tag(name:"solution", value:"Upgrade to nessus version 8.1.1 or later.
  For updates refer to Reference links.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.tenable.com");
  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2018-16");

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_nessus_web_server_detect.nasl");
  script_mandatory_keys("nessus/installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!nesPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:nesPort, exit_no_version:TRUE)) exit(0);

nesVer = infos['version'];
path = infos['location'];

if(version_in_range(version: nesVer, test_version: "8.0.0", test_version2: "8.1.0"))
{
  report = report_fixed_ver(installed_version:nesVer, fixed_version:"8.1.1", install_path:path);
  security_message(data:report, port:nesPort);
  exit(0);
}
exit(99);
