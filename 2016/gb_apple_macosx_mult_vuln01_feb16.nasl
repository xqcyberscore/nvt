###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_macosx_mult_vuln01_feb16.nasl 5513 2017-03-08 10:00:24Z teissa $
#
# Apple Mac OS X Multiple Vulnerabilities-01 February-2016
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806677");
  script_version("$Revision: 5513 $");
  script_cve_id("CVE-2016-1716", "CVE-2016-1717", "CVE-2016-1718", "CVE-2016-1719",
                "CVE-2016-1720", "CVE-2016-1721", "CVE-2016-1722", "CVE-2016-1729",
                "CVE-2015-7995");
  script_bugtraq_id(81274, 81277, 77325);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-03-08 11:00:24 +0100 (Wed, 08 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-02-03 18:07:12 +0530 (Wed, 03 Feb 2016)");
  script_name("Apple Mac OS X Multiple Vulnerabilities-01 February-2016");

  script_tag(name: "summary" , value:"This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Multiple flaws exists due to,
  - Multiple memory corruption errors in the parsing of disk images and IOHIDFamily
    API.
  - A type confusion error within libxslt.
  - Other multiple memory corruption errors.
  - An error when searching for scripting libraries.");

  script_tag(name: "impact" , value:"Successful exploitation will allow attacker
  to execute arbitrary code, override OSA script libraries.

  Impact Level: System");

  script_tag(name: "affected" , value:"Apple Mac OS X versions before 10.11.3");

  script_tag(name: "solution" , value:"Upgrade to Apple Mac OS X version
  10.11.3 or later. For more updates refer to https://www.apple.com");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name : "URL" , value : "https://support.apple.com/en-in/HT205731");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce/2016/Jan/msg00003.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version");
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
  if(version_is_less(version:osVer, test_version:"10.11.3"))
  {
    report = report_fixed_ver(installed_version:osVer, fixed_version:"10.11.3");
    security_message(data:report);
    exit(0);
  }
}
