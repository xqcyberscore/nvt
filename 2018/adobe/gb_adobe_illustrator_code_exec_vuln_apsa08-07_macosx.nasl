###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_illustrator_code_exec_vuln_apsa08-07_macosx.nasl 10495 2018-07-13 06:13:03Z ckuersteiner $
#
# Adobe Illustrator Remote Code Execution Vulnerability-Mac OS X (apsa08-07)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:adobe:illustrator";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813495");
  script_version("$Revision: 10495 $");
  script_cve_id("CVE-2008-3961");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-07-13 08:13:03 +0200 (Fri, 13 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-07-12 15:41:49 +0530 (Thu, 12 Jul 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Adobe Illustrator Remote Code Execution Vulnerability-Mac OS X (apsa08-07)");

  script_tag(name: "summary" , value:"The host is installed with Adobe Illustrator
  and is prone to a remote code execution vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw exists due to an error where a
  crafted file gets loaded by the application.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to execute arbitrary code on the affected system.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"Adobe Illustrator CS2 all versions.");

  script_tag(name: "solution" , value:"Upgrade to Adobe Illustrator CS3 or later.
  For updates refer to Reference links.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://www.adobe.com/support/security/advisories/apsa08-07.html");
  script_xref(name : "URL" , value : "https://www.adobe.com");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_illustrator_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Illustrator/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
adobeVer = infos['version'];
adobePath = infos['location'];

if(adobeVer =~ "^12\.")
{
  report = report_fixed_ver(installed_version:adobeVer, fixed_version:"Adobe Illustrator CS3", install_path:adobePath);
  security_message(data: report);
  exit(0);
}
exit(0);
