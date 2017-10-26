###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_virtualbox_oct2017-3236626_01_win.nasl 7554 2017-10-25 05:33:21Z cfischer $
#
# Oracle VirtualBox Security Updates (oct2017-3236626) 01 - Windows
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

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811980");
  script_version("$Revision: 7554 $");
  script_cve_id("CVE-2017-10407", "CVE-2017-3733", "CVE-2017-10428", "CVE-2017-10392", 
		"CVE-2017-10408");
  script_bugtraq_id(101370, 96269, 101362, 101368, 101371);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-10-25 07:33:21 +0200 (Wed, 25 Oct 2017) $");
  script_tag(name:"creation_date", value:"2017-10-18 12:48:43 +0530 (Wed, 18 Oct 2017)");
  script_name("Oracle VirtualBox Security Updates (oct2017-3236626) 01 - Windows");

  script_tag(name: "summary" , value:"The host is installed with Oracle VM
  VirtualBox and is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Multiple flaws exists due to multiple
  unspecified errors in 'core' component.");

  script_tag(name: "impact" , value:"Successful exploitation of these
  vulnerabilities will allow remote attackers to compromise availability
  confidentiality and integrity of the system.

  Impact Level: Application");

  script_tag(name: "affected" , value:"VirtualBox versions Prior to 5.1.30 on Windows.");

  script_tag(name: "solution" , value:"Upgrade to Oracle VirtualBox 5.1.30
  or later, For updates refer to https://www.virtualbox.org");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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
if(!virtualVer = get_app_version(cpe:CPE, nofork: TRUE)){
  exit(0);
}

## Grep for vulnerable version
if(version_is_less(version:virtualVer, test_version:"5.1.30"))
{
  report = report_fixed_ver( installed_version:virtualVer, fixed_version:"5.1.30");
  security_message(data:report);
  exit(0);
}
