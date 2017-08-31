###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_virtualbox_wddm_unspecified_vuln_nov14_lin.nasl 6715 2017-07-13 09:57:40Z teissa $
#
# Oracle Virtualbox WDDM Unspecified Vulnerability Nov14 (Linux)
#
# Authors:
# Deepmala  <kdeepmala@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804950");
  script_version("$Revision: 6715 $");
  script_cve_id("CVE-2014-6540");
  script_bugtraq_id(70493);
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-13 11:57:40 +0200 (Thu, 13 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-11-03 11:58:04 +0530 (Mon, 03 Nov 2014)");
  script_name("Oracle Virtualbox WDDM Unspecified Vulnerability Nov14 (Linux)");

  script_tag(name: "summary" , value:"This host is installed with Oracle VM
  VirtualBox and is prone to unspecified vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help of
  detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw is  due to an error related to
  Graphics driver (WDDM) for Windows Guests subcomponent.");

  script_tag(name: "impact" , value:"Successful exploitation will allow attackers to
  cause denial of service attack.

  Impact Level: Application");

  script_tag(name: "affected" , value:"VirtualBox version 4.1.x before 4.1.34, 4.2.x
  before 4.2.26, and 4.3.x before 4.3.14 on Linux");

  script_tag(name: "solution" , value:"Upgrade to Oracle VM VirtualBox version
  4.1.34 or 4.2.26 or 4.3.14 or later, For updates refer to
  https://www.virtualbox.org");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/61582/");
  script_xref(name:"URL", value:"http://cve.circl.lu/cve/CVE-2014-6540");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuoct2014-1972960.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_sun_virtualbox_detect_lin.nasl");
  script_mandatory_keys("Sun/VirtualBox/Lin/Ver");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

## Variable Initialization
virtualVer = "";

## Get version
if(!virtualVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(virtualVer =~ "^(4\.(1|2|3))")
{
  ## Check for vulnerable version
  if(version_in_range(version:virtualVer, test_version:"4.2.0", test_version2:"4.2.25")||
     version_in_range(version:virtualVer, test_version:"4.3.0", test_version2:"4.3.13") ||
     version_in_range(version:virtualVer, test_version:"4.1.0", test_version2:"4.1.33"))
  {
    security_message(0);
    exit(0);
  }
}
