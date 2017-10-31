###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_digital_editions_mult_vuln_aug17_win.nasl 7585 2017-10-26 15:03:01Z cfischer $
#
# Adobe Digital Editions Multiple Vulnerabilities Aug17 (Windows)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.811620");
  script_version("$Revision: 7585 $");
  script_cve_id("CVE-2017-11274", "CVE-2017-3091", "CVE-2017-11275", "CVE-2017-11276",
                "CVE-2017-11277", "CVE-2017-11278", "CVE-2017-11279", "CVE-2017-11280",
                "CVE-2017-11272");
  script_bugtraq_id(100194, 100193);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 17:03:01 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2017-08-10 16:25:08 +0530 (Thu, 10 Aug 2017)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Digital Editions Multiple Vulnerabilities Aug17 (Windows)");

  script_tag(name: "summary" , value:"This host is installed with Adobe Digital Edition
  and is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight", value:"Multiple flaws exists due to,
  - A buffer overflow vulnerability.

  - A memory corruption vulnerability.

  - XML External Entity Parsing vulnerability.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to execute arbitrary code on the target system, escalate privileges 
  and disclose sensitive information.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"Adobe Digital Edition prior to 4.5.6
  on Windows.");

  script_tag(name: "solution" , value:"Upgrade to Adobe Digital Edition version
  4.5.6 or later. For updates refer to http://www.adobe.com");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "https://helpx.adobe.com/security/products/Digital-Editions/apsb17-27.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_digital_edition_detect_win.nasl");
  script_mandatory_keys("AdobeDigitalEdition/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
digitalVer = "";

## Get version
if(!digitalVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Check Adobe Digital Edition vulnerable versions
if(version_is_less(version:digitalVer, test_version:"4.5.6"))
{
  report = report_fixed_ver(installed_version:digitalVer, fixed_version:"4.5.6");
  security_message(data:report);
  exit(0);
}
