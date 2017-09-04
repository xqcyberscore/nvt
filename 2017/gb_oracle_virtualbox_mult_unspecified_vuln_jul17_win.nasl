###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_virtualbox_mult_unspecified_vuln_jul17_win.nasl 7013 2017-08-25 13:17:51Z asteins $
#
# Oracle Virtualbox Multiple Unspecified Vulnerabilities July17 (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811529");
  script_version("$Revision: 7013 $");
  script_cve_id("CVE-2017-10204", "CVE-2017-10129", "CVE-2017-10210", "CVE-2017-10233", 
                "CVE-2017-10236", "CVE-2017-10237", "CVE-2017-10238", "CVE-2017-10238",
                "CVE-2017-10240", "CVE-2017-10241", "CVE-2017-10242", "CVE-2017-10235",
                "CVE-2017-10209", "CVE-2017-10187");
  script_bugtraq_id(99631, 99638, 99640, 99642, 99645, 99667, 99668, 99683, 99687, 99689,
                    99705, 99709, 99711);
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-08-25 15:17:51 +0200 (Fri, 25 Aug 2017) $");
  script_tag(name:"creation_date", value:"2017-07-19 11:38:31 +0530 (Wed, 19 Jul 2017)");
  script_name("Oracle Virtualbox Multiple Unspecified Vulnerabilities July17 (Windows)");

  script_tag(name: "summary" , value:"This host is installed with Oracle VM
  VirtualBox and is prone to multiple unspecified vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Multiple flaws are due to multiple 
  unspecified errors related to core component of the application.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to have an impact on availability, confidentiality and integrity.

  Impact Level: Application");

  script_tag(name: "affected" , value:"VirtualBox versions prior to 5.1.24
  on Windows.");

  script_tag(name: "solution" , value:"Upgrade to Oracle VirtualBox 5.1.24 or later,
  For updates refer to https://www.virtualbox.org");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_sun_virtualbox_detect_win.nasl");
  script_mandatory_keys("Oracle/VirtualBox/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
virtualVer = "";
report = "";

## Get version
if(!virtualVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Grep for vulnerable version
if(version_is_less(version:virtualVer, test_version:"5.1.24"))
{
  report = report_fixed_ver( installed_version:virtualVer, fixed_version:"5.1.24");
  security_message(data:report);
  exit(0);
}
