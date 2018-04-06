###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apple_quicktime_mult_vuln_jan09_win.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Apple QuickTime Multiple Vulnerabilities - Jan09 (Windows)
#
# Authors:
# Chandan S <schandan@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_insight = "- Application fails in handling of RTSP URLs, THKD atoms in QTVR (QuickTime
    Virtual Reality) movie files and jpeg atoms in QT movie files.
  - Popping of overflow errors while processing an AVI movie file.
  - Player fails to handle MPEG-2 video files with MP3 audio content and
    H.263 encoded movie files.
  - Signedness flaw in handling of Cinepak encoded movie files.
  - Input validation flaw exists in the QT MPEG-2 Playback Component.

  For more information refer,
  http://lists.apple.com/archives/security-announce/2009/Jan/msg00000.html";

tag_impact = "Attackers can execute arbitrary code by sending maliciously crafted RTSP
  URLs and viewing a maliciously crafted QTVR file can lead to unexpected
  application termination.
  Impact Level: Application";
tag_affected = "Apple QuickTime before 7.60.92.0 on Windows (Any).";
tag_solution = "Upgrade to Apple QuickTime version 7.60.92.0 or later,
  http://www.apple.com/quicktime/download/";
tag_summary = "The host is installed with Apple QuickTime and is prone to
  Multiple Vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900074");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-01-23 16:33:16 +0100 (Fri, 23 Jan 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0001", "CVE-2009-0002", "CVE-2009-0003", "CVE-2009-0004",
                "CVE-2009-0005", "CVE-2009-0006", "CVE-2009-0007", "CVE-2009-0008");
  script_bugtraq_id(33393);
  script_name("Apple QuickTime Multiple Vulnerabilities - Jan09 (Windows)");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce/2009/Jan/msg00000.html");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce/2009/Jan/msg00001.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_apple_quicktime_detection_win_900124.nasl");
  script_mandatory_keys("QuickTime/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

qtVer = get_kb_item("QuickTime/Win/Ver");
if(!qtVer){
  exit(0);
}

# QuickTime version <= 7.5
if(version_is_less_equal(version:qtVer, test_version:"7.5")){
  security_message(0);
}
