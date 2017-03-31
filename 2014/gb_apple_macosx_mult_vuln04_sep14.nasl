###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_macosx_mult_vuln04_sep14.nasl 2825 2016-03-10 08:11:16Z benallard $
#
# Apple Mac OS X Multiple Vulnerabilities -04 Sep14
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804850");
  script_version("$Revision: 2825 $");
  script_cve_id("CVE-2013-1862", "CVE-2013-1896", "CVE-2014-1256", "CVE-2014-1265",
                "CVE-2014-1259", "CVE-2013-6629", "CVE-2013-5986", "CVE-2013-5987",
                "CVE-2013-4073", "CVE-2013-4113", "CVE-2013-4248", "CVE-2013-6420",
                "CVE-2014-1246", "CVE-2014-1247", "CVE-2014-1248", "CVE-2014-1249",
                "CVE-2014-1250", "CVE-2014-1245");
  script_bugtraq_id(59826, 61129, 65777, 63676, 65208, 64525, 60843, 61128, 61776,
                    64225);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2016-03-10 09:11:16 +0100 (Thu, 10 Mar 2016) $");
  script_tag(name:"creation_date", value:"2014-09-22 15:50:08 +0530 (Mon, 22 Sep 2014)");

  script_name("Apple Mac OS X Multiple Vulnerabilities -04 Sep14");

  script_tag(name: "summary" , value:"This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Multiple flaws exist. For more details
  refer the reference section.");

  script_tag(name: "impact" , value:"Successful exploitation will allow attackers
  to conduct cross-site scripting, change the system clock, bypass security
  restrictions, disclose sensitive information, compromise the affected system,
  and denial of service attacks.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"Apple Mac OS X version 10.7.x through
  10.7.5, 10.8.x through 10.8.5 and 10.9.x before 10.9.2");

  script_tag(name: "solution" , value:"Run Mac Updates. For more information
  refer link, http://support.apple.com/kb/HT6150

  NOTE: Please ignore the warning if the update is already applied.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT6150");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/54960");
  script_summary("Check for the vulnerable version of Apple Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/uname", "ssh/login/osx_name", "ssh/login/osx_version");
  exit(0);
}

include("version_func.inc");

## Variable Initialization
osName = "";
osVer = "";

## Get the OS name
osName = get_kb_item("ssh/login/osx_name");
if(!osName){
  exit (0);
}

## Get the OS Version
osVer = get_kb_item("ssh/login/osx_version");
if(!osVer){
 exit(0);
}

## Check for the Mac OS X
if("Mac OS X" >< osName)
{
  ## Check the affected OS versions
  if(version_in_range(version:osVer, test_version:"10.9.0", test_version2:"10.9.1")||
     version_in_range(version:osVer, test_version:"10.8.0", test_version2:"10.8.5")||
     version_in_range(version:osVer, test_version:"10.7.0", test_version2:"10.7.5"))
  {
    security_message(0);
    exit(0);
  }
}
