###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_thunderbird_mult_vuln_aug13_macosx.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Mozilla Thunderbird Multiple Vulnerabilities - August 13 (Mac OS X)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "
  Impact Level: System/Application";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.803857");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-1701", "CVE-2013-1706", "CVE-2013-1707", "CVE-2013-1709",
                "CVE-2013-1710", "CVE-2013-1712", "CVE-2013-1713", "CVE-2013-1714",
                "CVE-2013-1717");
  script_bugtraq_id(61641);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-08-08 15:49:37 +0530 (Thu, 08 Aug 2013)");
  script_name("Mozilla Thunderbird Multiple Vulnerabilities - August 13 (Mac OS X)");

  tag_summary =
"The host is installed with Mozilla Thunderbird and is prone to multiple
vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Multiple flaws due to,
- Error in crypto.generateCRMFRequest function.
- Does not properly restrict local-filesystem access by Java applets.
- Multiple Unspecified vulnerabilities in the browser engine.
- Multiple untrusted search path vulnerabilities updater.exe.
- Web Workers implementation is not properly restrict XMLHttpRequest calls.
- Usage of incorrect URI within unspecified comparisons during enforcement
  of the Same Origin Policy.
- Improper handling of interaction between FRAME elements and history.
- Stack-based buffer overflow in Mozilla Updater and maintenanceservice.exe.";

  tag_impact =
"Successful exploitation will allow attackers to execute arbitrary code,
obtain potentially sensitive information, gain escalated privileges, bypass
security restrictions, perform unauthorized actions and other attacks may
also be possible.";

  tag_affected =
"Mozilla Thunderbird before 17.0.8 on Mac OS X";

  tag_solution =
"Upgrade to version 17.0.8 or later,
For updates refer to http://www.mozilla.org/en-US/thunderbird";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/54413");
  script_xref(name : "URL" , value : "https://bugzilla.mozilla.org/show_bug.cgi?id=406541");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2013/mfsa2013-75.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("ThunderBird/MacOSX/Version");
  exit(0);
}


include("version_func.inc");

# Variable Initialization
tbVer = "";

# Thunderbird Check
tbVer = get_kb_item("ThunderBird/MacOSX/Version");

if(tbVer)
{
  # Grep for Thunderbird version
  if(version_is_less(version:tbVer, test_version:"17.0.8"))
  {
    security_message(0);
    exit(0);
  }
}
