###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_quicktime_mult_vuln_jun13_win.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Apple QuickTime Multiple Vulnerabilities - June13 (Windows)
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary code,
  memory corruption or buffer overflow.
  Impact Level: System/Application";

tag_affected = "QuickTime Player version prior to 7.7.4 on Windows";
tag_insight = "Multiple flaws due to,
  Boundary error when handling
   - FPX files
   - 'enof' and 'mvhd' atoms
   - H.263 and H.264 encoded movie files
   - A certain value in a dref atom within a MOV file
   - A channel_mode value of MP3 files within the CoreAudioToolbox component
  Unspecified error when handling TeXML files, JPEG encoded data, QTIF files";
tag_solution = "Upgrade to version 7.7.4 or later,
  For updates refer to http://support.apple.com/downloads";
tag_summary = "This host is installed with QuickTime Player and is prone
  to multiple vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803809");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-1022", "CVE-2013-1021", "CVE-2013-1020", "CVE-2013-1019",
                "CVE-2013-1018", "CVE-2013-1017", "CVE-2013-1016", "CVE-2013-1015",
                "CVE-2013-0989", "CVE-2013-0988", "CVE-2013-0987", "CVE-2013-0986");
  script_bugtraq_id(60104, 60103, 60108, 60102, 60098, 60097,
                    60092, 60110, 60101, 60100, 60109, 60099);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-06-07 18:15:48 +0530 (Fri, 07 Jun 2013)");
  script_name("Apple QuickTime Multiple Vulnerabilities - June13 (Windows)");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT5770");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/53520");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce/2013/May/msg00001.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_quicktime_detection_win_900124.nasl");
  script_mandatory_keys("QuickTime/Win/Ver");
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

## Check for QuickTime Player Version less than 7.7.4
if(version_is_less(version:quickVer, test_version:"7.7.4"))
{
  security_message(0);
  exit(0);
}
