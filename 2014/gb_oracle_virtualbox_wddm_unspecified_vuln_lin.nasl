###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_virtualbox_wddm_unspecified_vuln_lin.nasl 6715 2017-07-13 09:57:40Z teissa $
#
# Oracle VM VirtualBox Graphics Driver(WDDM) Unspecified Vulnerability (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804435";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6715 $");
  script_cve_id("CVE-2014-2441");
  script_bugtraq_id(66868);
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-13 11:57:40 +0200 (Thu, 13 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-04-18 12:54:10 +0530 (Fri, 18 Apr 2014)");
  script_name("Oracle VM VirtualBox Graphics Driver(WDDM) Unspecified Vulnerability (Linux)");

  tag_summary =
"This host is installed with Oracle VM VirtualBox and is prone to unspecified
vulnerability.";

  tag_vuldetect =
"Get the installed version of Oracle VM VirtualBox and check the version is
vulnerable or not.";

  tag_insight =
"The flaw is  due to an error within the Graphics driver(WDDM) for Windows
guests component and can be exploited by disclose, update, insert, or delete
certain data and to cause a crash.";

  tag_impact =
"Successful exploitation will allow local users to disclose sensitive
information, manipulate certain data, and cause a DoS (Denial of
Service).

Impact Level: System/Application";

  tag_affected =
"Oracle Virtualization VirtualBox 4.1.x before 4.1.32, 4.2.x before 4.2.24,
and 4.3.x before 4.3.10 on Linux";

  tag_solution =
"Upgrade to Oracle VM VirtualBox version 4.1.32, 4.2.24, 4.3.10 or later,
For updates refer to https://www.virtualbox.org";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/57937");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/cpuapr2014-1972952.html");
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
if(!virtualVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

if(virtualVer =~ "^(4\.(1|2|3))")
{
  ## Check for vulnerable version
  if(version_in_range(version:virtualVer, test_version:"4.2.0", test_version2:"4.2.23")||
     version_in_range(version:virtualVer, test_version:"4.3.0", test_version2:"4.3.9") ||
     version_in_range(version:virtualVer, test_version:"4.1.0", test_version2:"4.1.31"))
  {
    security_message(0);
    exit(0);
  }
}
