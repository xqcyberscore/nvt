###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_silverlight_ms13-052_macosx.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Microsoft Silverlight Remote Code Execution Vulnerabilities-2861561 (Mac OS X)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation could allow an attacker to execute arbitrary code,
  bypass security mechanism and take complete control of an affected system.
  Impact Level: System/Application";

tag_affected = "Microsoft Silverlight version 5 on Mac OS X";
tag_insight = "Multiple flaws due to,
  - Improper handling of TrueType font and multidimensional arrays of
    small structures
  - Improper Handling of null pointer";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms13-052";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS13-052.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902987");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-3129", "CVE-2013-3131", "CVE-2013-3178");
  script_bugtraq_id(60978, 60932, 60938);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-07-11 11:32:39 +0530 (Thu, 11 Jul 2013)");
  script_name("Microsoft Silverlight Remote Code Execution Vulnerabilities-2861561 (Mac OS X)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/54025");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2861561");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms13-052");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_ms_silverlight_detect_macosx.nasl");
  script_mandatory_keys("MS/Silverlight/MacOSX/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

## Variable Initialization
slightVer = "";

## Get the version from KB
slightVer = get_kb_item("MS/Silverlight/MacOSX/Ver");

if(!slightVer || !(slightVer =~ "^5\.")){
  exit(0);
}

if(version_in_range(version:slightVer, test_version:"5.1", test_version2:"5.1.20512"))
{
  security_message(0);
  exit(0);
}
