###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_spoofing_n_xss_vuln_HT208116.nasl 7604 2017-11-01 06:48:12Z asteins $
#
# Apple Safari Spoofing and Cross-Site Scripting Vulnerabilities - HT208116 
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

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811782");
  script_version("$Revision: 7604 $");
  script_cve_id("CVE-2017-7085", "CVE-2017-7089", "CVE-2017-7106", "CVE-2017-7081",
                "CVE-2017-7087", "CVE-2017-7090", "CVE-2017-7091", "CVE-2017-7092",
                "CVE-2017-7093", "CVE-2017-7094", "CVE-2017-7095", "CVE-2017-7096",
                "CVE-2017-7098", "CVE-2017-7099", "CVE-2017-7100", "CVE-2017-7102",
                "CVE-2017-7104", "CVE-2017-7107", "CVE-2017-7109", "CVE-2017-7111",
                "CVE-2017-7117", "CVE-2017-7120", "CVE-2017-7142", "CVE-2017-7144");
  script_bugtraq_id(100895, 100893, 100893, 100995, 100994, 101006, 100998, 101005,
                    100996, 100991);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-11-01 07:48:12 +0100 (Wed, 01 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-09-21 11:33:23 +0530 (Thu, 21 Sep 2017)");
  script_name("Apple Safari Spoofing and Cross-Site Scripting Vulnerabilities - HT208116");

  script_tag(name:"summary" , value:"This host is installed with Apple Safari
  and is prone to spoofing and cross-site scripting vulnerabilities.");

  script_tag(name:"vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight" , value:"Multiple flaws exists due to,

  - Multiple inconsistent user interface issues.

  - A logic issue exists in the handling of the parent-tab.

  - An inconsistent user interface issue.

  - Multiple memory corruption issues.

  - A permissions issue existed in the handling of web browser cookies.

  - An information leakage issue existed in the handling of website data in 
    Safari Private windows.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to conduct cross site scripting and address bar spoofing attacks,
  execute arbitrary code or cause a denial of service, obtain sensitive 
  information and bypass security.

  Impact Level: Application");

  script_tag(name: "affected" , value:"Apple Safari versions before 11.0");

  script_tag(name: "solution" , value:"Upgrade to Apple Safari 11.0 or later.
  For updates refer to http://www.apple.com/support.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name : "URL" , value : "https://support.apple.com/en-us/HT208116");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version");
  exit(0);
}


# Code starts from here

include("version_func.inc");
include("host_details.inc");

# Variable Initialization
safVer = "";

## Get Apple Safari version
if(!safVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Check for Apple Safari Versions less than 11
if(version_is_less(version:safVer, test_version:"11.0"))
{
  report = report_fixed_ver(installed_version:safVer, fixed_version:"11.0");
  security_message(data:report);
  exit(0);
}
exit(0);
