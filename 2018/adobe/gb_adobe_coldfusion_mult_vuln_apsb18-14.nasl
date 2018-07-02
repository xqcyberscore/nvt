###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_coldfusion_mult_vuln_apsb18-14.nasl 10374 2018-07-02 04:44:41Z asteins $
#
# Adobe ColdFusion Multiple Vulnerabilities-APSB18-14
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:coldfusion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813083");
  script_version("$Revision: 10374 $");
  script_cve_id("CVE-2018-4938", "CVE-2018-4939", "CVE-2018-4940", "CVE-2018-4941",
                "CVE-2018-4942");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-07-02 06:44:41 +0200 (Mon, 02 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-04-12 12:11:00 +0530 (Thu, 12 Apr 2018)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Adobe ColdFusion Multiple Vulnerabilities-APSB18-14");

  script_tag(name:"summary", value:"This host is running Adobe ColdFusion and is 
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An insecure library loading error.

  - Multiple input validation errors.

  - An unsafe XML parsing error.

  - The deserialization of untrusted data.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the affected application,
  disclose sensitive information and also to escalate privileges.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"Adobe ColdFusion version 11 before Update 14");

  script_tag(name:"solution", value:"Upgrade Adobe ColdFusion 11 Update 14 or later.
  For details refer to Reference links.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.adobe.com/products/coldfusion/download-trial/try.html");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/coldfusion/apsb18-14.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_coldfusion_detect.nasl");
  script_mandatory_keys("coldfusion/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!cfPort = get_app_port(cpe:CPE)){
  exit(0);
}

infos = get_app_version_and_location(cpe:CPE, port:cfPort, exit_no_version:TRUE);
cfdVer = infos['version'];
cfdPath = infos['location'];

## https://helpx.adobe.com/coldfusion/kb/coldfusion-11-update-14.html
if(version_in_range(version:cfdVer, test_version:"11.0", test_version2:"11.0.14.307975"))
{
  report = report_fixed_ver(installed_version:cfdVer, fixed_version:"11.0.14.307976", install_path:cfdPath);
  security_message(data:report, port:cfPort);
  exit(0);
}
exit(0);
