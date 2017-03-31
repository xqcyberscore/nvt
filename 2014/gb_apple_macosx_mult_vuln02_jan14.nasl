###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_macosx_mult_vuln02_jan14.nasl 30092 2014-01-20 19:13:47Z Jan$
#
# Apple Mac OS X Multiple Vulnerabilities - 02 Jan14
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804061";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 3521 $");
  script_cve_id("CVE-2013-0975", "CVE-2013-0982", "CVE-2013-0983",
                "CVE-2013-0985", "CVE-2013-0990", "CVE-2013-1024");
  script_bugtraq_id(60365, 60366, 60367, 60331, 60369, 60368);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2016-06-15 12:46:01 +0200 (Wed, 15 Jun 2016) $");
  script_tag(name:"creation_date", value:"2014-01-20 19:13:47 +0530 (Mon, 20 Jan 2014)");
  script_name("Apple Mac OS X Multiple Vulnerabilities - 02 Jan14");

  tag_summary =
"This host is running Apple Mac OS X and is prone to multiple vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Multiple flaws are due to,
- File sharing allows remote authenticated users to modify files outside the
  shared directory
- CoreMedia Playback is not properly initialize memory during the process of
  text tracks.
- Private Browsing feature in CFNetwork is not preventing storage of permanent
  cookies.
- Disk management is not properly authenticate attempts to disable Filevault.
- Stack consumption vulnerability in CoreAnimation.
- Buffer overflow in QuickDraw Manager.";

  tag_impact =
"Successful exploitation will allow attackers to, execute arbitrary code or
cause a denial of service.

Impact Level: System/Application";

  tag_affected =
"Apple Mac OS X version before 10.8.4";

  tag_solution =
"Run Mac Updates and install OS X v10.8.4 Supplemental Update,
For updates refer to http://support.apple.com/kb/HT5784";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT5784");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT6001");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/53684");
  script_xref(name : "URL" , value : "http://prod.lists.apple.com/archives/security-announce/2013/Jun/msg00000.html");
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
  if(version_is_less(version:osVer, test_version:"10.8.4"))
  {
    security_message(0);
    exit(0);
  }
}
