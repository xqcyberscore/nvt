###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_macosx_su12-003.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Mac OS X 'Internet plug-ins' Unspecified Vulnerability (2012-003)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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

tag_insight = "The flaw is cause due to the unspecified error in the Internet plug-ins.

  NOTE: For more information on the vulnerabilities refer to the links below.";

tag_impact = "Unknown impact
  Impact Level: System/Application";
tag_affected = "Internet plug-ins for Adobe Flash Player on Mac OS X";
tag_solution = "Run Mac Updates and update the Security Update 2012-003
  For updates refer to http://support.apple.com/kb/DL1533";
tag_summary = "This host is missing an important security update according to
  Mac OS X 10.5.x Update/Mac OS X Security Update 2012-003.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903027");
  script_version("$Revision: 9352 $");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-05-21 14:38:50 +0530 (Mon, 21 May 2012)");
  script_name("Mac OS X 'Internet plug-ins' Unspecified Vulnerability (2012-003)");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/DL1533");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT1222");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT5283");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/112742/APPLE-SA-2012-05-14-2.txt");
  script_xref(name : "URL" , value : "http://prod.lists.apple.com/archives/security-announce/2012/May/msg00004.html");

  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_copyright("Copyright (C) 2012 SecPod");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("pkg-lib-macosx.inc");
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

## Check for the Mac OS X and Mac OS X Server
if("Mac OS X" >< osName || "Mac OS X Server" >< osName)
{
  ## Check the affected OS versions
  if(version_in_range(version:osVer, test_version:"10.5.0", test_version2:"10.5.8"))
  {
    ## Check for the security update 2012.003
    if(isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2012.003"))
    {
      security_message(0);
      exit(0);
    }
  }
}
