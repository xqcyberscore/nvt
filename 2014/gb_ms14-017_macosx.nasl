###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms14-017_macosx.nasl 9354 2018-04-06 07:15:32Z cfischer $
#
# Microsoft Office Remote Code Execution Vulnerabilities-2949660 (Mac OS X)
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804427");
  script_version("$Revision: 9354 $");
  script_cve_id("CVE-2014-1757", "CVE-2014-1758", "CVE-2014-1761");
  script_bugtraq_id(66385, 66614, 66629);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:15:32 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2014-04-09 10:25:33 +0530 (Wed, 09 Apr 2014)");
  script_tag(name:"solution_type", value: "VendorFix");
  script_name("Microsoft Office Remote Code Execution Vulnerabilities-2949660 (Mac OS X)");

  tag_summary =
"This host is missing a critical security update according to
Microsoft Bulletin MS14-017.";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"Multiple flaws are due to an error within,
 - Microsoft Word when handling certain RTF-formatted data can be exploited to
   corrupt memory.
 - Microsoft Office File Format Converter when handling certain files can be
   exploited to corrupt memory.
 - Microsoft Word when handling certain files can be exploited to cause a
   stack-based buffer overflow.";

  tag_impact =
"Successful exploitation will allow remote attackers to execute the arbitrary
code, cause memory corruption and compromise the system.

Impact Level: System/Application ";

  tag_affected =
"Microsoft Office 2011 on Mac OS X";

  tag_solution =
"Apply the patch from below link,
https://technet.microsoft.com/en-us/security/bulletin/ms14-017";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"package");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/57577");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms14-017");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_microsoft_office_detect_macosx.nasl");
  script_mandatory_keys("MS/Office/MacOSX/Ver");
  exit(0);
}


include("version_func.inc");

## Variable Initialization
offVer = "";

## Get the version from KB
offVer = get_kb_item("MS/Office/MacOSX/Ver");

## check the version from KB
if(!offVer || !(offVer =~ "^(14)")){
  exit(0);
}

## Check for Office Version < 2011 (14.4.1)
if(version_in_range(version:offVer, test_version:"14.0", test_version2:"14.4.0"))
{
  security_message(0);
  exit(0);
}
