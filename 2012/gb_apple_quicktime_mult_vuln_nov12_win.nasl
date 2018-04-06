###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_quicktime_mult_vuln_nov12_win.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Apple QuickTime Multiple Vulnerabilities - Nov12 (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary code or
  cause a buffer overflow condition.
  Impact Level: System/Application";
tag_affected = "QuickTime Player version prior to 7.7.3 on Windows";
tag_insight = "- Multiple boundary errors exists when handling a PICT file, a Targa file,
    the transform attribute of 'text3GTrack' elements and the 'rnet' box
    within MP4 file.
  - Use-after-free errors exists when handling '_qtactivex_' parameters within
    an HTML object and 'Clear()' method.";
tag_solution = "Upgrade to QuickTime Player version 7.7.3 or later,
  For updates refer to http://support.apple.com/downloads/";
tag_summary = "This host is installed with Apple QuickTime and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803047");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2011-1374", "CVE-2012-3757", "CVE-2012-3751", "CVE-2012-3758",
                "CVE-2012-3752", "CVE-2012-3753", "CVE-2012-3754", "CVE-2012-3755",
                "CVE-2012-3756");
  script_bugtraq_id(56438);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-11-09 13:08:03 +0530 (Fri, 09 Nov 2012)");
  script_name("Apple QuickTime Multiple Vulnerabilities - Nov12 (Windows)");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT5581");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51226");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce/2012/Nov/msg00002.html");

  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_apple_quicktime_detection_win_900124.nasl");
  script_require_keys("QuickTime/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

## Variable Initialization
quickVer = "";

## Get the version from KB
quickVer = get_kb_item("QuickTime/Win/Ver");
if(!quickVer){
  exit(0);
}

## Check for QuickTime Player Version less than 7.7.3
if(version_is_less(version:quickVer, test_version:"7.7.3")){
  security_message(0);
}
