##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_digital_editions_mult_info_disc_vuln_apsb17-39_win.nasl 7790 2017-11-16 13:11:14Z santu $
#
# Adobe Digital Editions Multiple Information Disclosure Vulnerabilities - APSB17-39 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:digital_editions";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812090");
  script_version("$Revision: 7790 $");
  script_cve_id("CVE-2017-11273", "CVE-2017-11297", "CVE-2017-11298", "CVE-2017-11299",
                "CVE-2017-11300", "CVE-2017-11301");
  script_bugtraq_id(101839);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification",  value:"$Date: 2017-11-16 14:11:14 +0100 (Thu, 16 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-11-16 10:51:03 +0530 (Thu, 16 Nov 2017)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Digital Editions Multiple Information Disclosure Vulnerabilities - APSB17-39 (Windows)");

  script_tag(name: "summary" , value:"This host is installed with Adobe Digital Edition
  and is prone to multiple information disclosure vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight", value:"Multiple flaws exists due to unsafe parsing
  of XML external entities, multiple out-of-bounds read errors and memory corruption
  errors.");

  script_tag(name: "impact" , value:"Successful exploitation will allow attackers
  to gain access to potentially sensitive information.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"Adobe Digital Edition prior to 4.5.7
  on Windows.");

  script_tag(name: "solution" , value:"Upgrade to Adobe Digital Edition version
  4.5.7 or later. For updates refer to http://www.adobe.com");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "https://helpx.adobe.com/security/products/Digital-Editions/apsb17-39.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_digital_edition_detect_win.nasl");
  script_mandatory_keys("AdobeDigitalEdition/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

digitalVer = "";
digitalPath = "";
infos = "";

infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE);
digitalVer = infos['version'];
digitalPath = infos['location'];

if(version_is_less(version:digitalVer, test_version:"4.5.7"))
{
  report = report_fixed_ver(installed_version:digitalVer, fixed_version:"4.5.7", install_path:digitalPath);
  security_message(data:report);
  exit(0);
}
exit(0);
