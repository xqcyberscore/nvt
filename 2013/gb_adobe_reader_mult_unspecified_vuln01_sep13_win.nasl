###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_mult_unspecified_vuln01_sep13_win.nasl 31791 2013-09-17 15:50:32Z sep$
#
# Adobe Reader Multiple Unspecified Vulnerabilities-01 Sep13 (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803893");
  script_version("$Revision: 8210 $");
  script_cve_id("CVE-2013-3351", "CVE-2013-3352", "CVE-2013-3353", "CVE-2013-3354",
                "CVE-2013-3355", "CVE-2013-3356", "CVE-2013-3357", "CVE-2013-3358");
  script_bugtraq_id(62429, 62431, 62428, 62432, 62435, 62436, 62433, 62430);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-12-21 11:26:31 +0100 (Thu, 21 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-09-17 15:50:32 +0530 (Tue, 17 Sep 2013)");
  script_name("Adobe Reader Multiple Unspecified Vulnerabilities-01 Sep13 (Windows)");

  tag_summary = "This host is installed with Adobe Reader and is prone to multiple unspecified
vulnerabilities.";

  tag_vuldetect = "Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight = "Multiple flaws are due to,

- An integer overflow error when handling U3D PCX external texture.

- Other multiple unspecified and integer overflow errors.";

  tag_impact = "Successful exploitation will allow attacker to execute arbitrary code,
cause a denial of service condition and potentially allow to take control
of the affected system.

Impact Level: System/Application";

  tag_affected = "Adobe Reader X Version 10.x prior to 10.1.8 on Windows

Adobe Reader XI Version 11.x prior to 11.0.04 on Windows";

  tag_solution = "Update to Adobe Reader Version 11.0.04 or 10.1.8 or later,
For updates refer to http://get.adobe.com/reader";

  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/54694");
  script_xref(name : "URL" , value : "https://www.adobe.com/support/security/bulletins/apsb13-22.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Reader/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!readerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(readerVer && readerVer =~ "^10|11")
{
  ## Check Adobe Reader version is 10.x <= 10.1.7 and 11.x <= 11.0.03
  if(version_in_range(version:readerVer, test_version:"10.0", test_version2: "10.1.7")||
     version_in_range(version:readerVer, test_version:"11.0", test_version2: "11.0.03"))
  {
    security_message(0);
    exit(0);
  }
}
