###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_virtualbox_unspecified_vuln01_jan16_lin.nasl 5759 2017-03-29 09:01:08Z teissa $
#
# Oracle Virtualbox Unspecified Vulnerability - 01 Jan16 (Linux)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806991");
  script_version("$Revision: 5759 $");
  script_cve_id("CVE-2016-0495", "CVE-2015-3195");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-03-29 11:01:08 +0200 (Wed, 29 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-01-22 16:51:21 +0530 (Fri, 22 Jan 2016)");
  script_name("Oracle Virtualbox Unspecified Vulnerability - 01 Jan16 (Linux)");

  script_tag(name: "summary" , value:"This host is installed with Oracle VM
  VirtualBox and is prone to unspecified vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw exists due to some unspecified
  error.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to have an impact on availability.

  Impact Level: Application");

  script_tag(name: "affected" , value:"VirtualBox versions prior to 4.3.36
  and 5.0.14  on Linux.");

  script_tag(name: "solution" , value:"Upgrade to Oracle VirtualBox version
  4.3.36, 5.0.14 or later on Linux. For updates refer to https://www.virtualbox.org");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/cpujan2016-2367955.html");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_sun_virtualbox_detect_lin.nasl");
  script_mandatory_keys("Sun/VirtualBox/Lin/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
virtualVer = "";

## Get version
if(!virtualVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Grep for vulnerable version
if(version_in_range(version:virtualVer, test_version:"4.0.0", test_version2:"4.3.35"))
{
  fix = "4.3.36";
  VULN = TRUE;
}

else if(version_in_range(version:virtualVer, test_version:"5.0.0", test_version2:"5.0.13"))
{
  fix = "5.0.14";
  VULN = TRUE;
}

if(VULN)
{
  report = report_fixed_ver( installed_version:virtualVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}
