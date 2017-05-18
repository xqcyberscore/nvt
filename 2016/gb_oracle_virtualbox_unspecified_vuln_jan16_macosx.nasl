###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_virtualbox_unspecified_vuln_jan16_macosx.nasl 5689 2017-03-23 10:00:49Z teissa $
#
# Oracle Virtualbox Unspecified Vulnerability Jan16 (Mac OS X)
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
  script_oid("1.3.6.1.4.1.25623.1.0.806989");
  script_version("$Revision: 5689 $");
  script_cve_id("CVE-2016-0602");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-03-23 11:00:49 +0100 (Thu, 23 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-01-22 16:40:56 +0530 (Fri, 22 Jan 2016)");
  script_name("Oracle Virtualbox Unspecified Vulnerability Jan16 (Mac OS X)");

  script_tag(name: "summary" , value:"This host is installed with Oracle VM
  VirtualBox and is prone to unspecified vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw exists due to some unspecified
  error.");

  script_tag(name: "impact" , value:"Successful exploitation will allow local
  attackers to have an impact on confidentiality, integrity, and availability.

  Impact Level: Application");

  script_tag(name: "affected" , value:"VirtualBox versions prior to 5.0.14
  on Mac OS X.");

  script_tag(name: "solution" , value:"Upgrade to Oracle VirtualBox version
  5.0.14 or later on Mac OS X. For updates refer to https://www.virtualbox.org");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/cpujan2016-2367955.html");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_oracle_virtualbox_detect_macosx.nasl");
  script_mandatory_keys("Oracle/VirtualBox/MacOSX/Version");
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
if(version_in_range(version:virtualVer, test_version:"5.0.0", test_version2:"5.0.13"))
{
  report = report_fixed_ver(installed_version:virtualVer, fixed_version:"5.0.14");
  security_message(data:report);
  exit(0);
}
