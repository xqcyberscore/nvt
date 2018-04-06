###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apple_quicktime_mult_vuln_sep09.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Apple QuickTime Multiple Vulnerabilities - Sep09
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code in the
  context of an affected application, and can cause Denial of Service.
  Impact Level: Application";
tag_affected = "Apple QuickTime before 7.6.4 on Windows.";
tag_insight = "- A memory corruption issue exists when handling 'H.264' movie files.
  - An error in the parsing of 'MPEG-4' video files which causes buffer
    overflow.
  - An integer overflow error when processing the 'SectorShift' and 'cSectFat'
    fields of a FlashPix file header. This can be exploited to cause a
    heap-based buffer overflow via a specially crafted FlashPix '.fpx' file.
  - A boundary error exists when processing samples from a 'H.264' encoded MOV
    file. This can be exploited to cause a heap-based buffer overflow via a
    specially crafted 'MOV' file.";
tag_solution = "Upgrade to Apple QuickTime version 7.6.4 or later,
  http://www.apple.com/quicktime/download/";
tag_summary = "The host is installed with Apple QuickTime and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901017");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-09-11 18:01:06 +0200 (Fri, 11 Sep 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2202", "CVE-2009-2203", "CVE-2009-2798", "CVE-2009-2799");
  script_bugtraq_id(36328);
  script_name("Apple QuickTime Multiple Vulnerabilities - Sep09");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT3859");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce/2009/Sep/msg00002.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_apple_quicktime_detection_win_900124.nasl");
  script_require_keys("QuickTime/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

qtVer = get_kb_item("QuickTime/Win/Ver");

if(qtVer)
{
  # QuickTime version < 7.6.4
  if(version_is_less(version:qtVer, test_version:"7.6.4")){
    security_message(0);
  }
}
