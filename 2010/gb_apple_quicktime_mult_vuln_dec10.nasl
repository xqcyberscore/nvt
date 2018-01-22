###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_quicktime_mult_vuln_dec10.nasl 8457 2018-01-18 07:58:32Z teissa $
#
# Apple QuickTime Multiple vulnerabilities - Dec10 (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation could allow attackers to gain knowledge of sensitive
  information or execute arbitrary code via a malicious video or web page.
  Impact Level: Application";
tag_affected = "QuickTime Player version prior to 7.6.9";
tag_insight = "The multiple flaws are due to,
  - A heap overflow error when processing Track Header atoms, which could be
    exploited to execute arbitrary code via a malicious video or web page.
  - A filesystem permission error may allow a local user on a Windows system to
    access the contents of the Apple Computer directory in the user's profile.
  - A memory corruption error when handling PICT files.
  - An uninitialized memory access when processing FlashPix images.
  - A memory corruption error when processing panorama atoms in QTVR (QuickTime
    Virtual Reality) movie files.
  - An integer overflow error when processing movie files.";
tag_solution = "Upgrade to QuickTime Player version 7.6.9 or later
  For updates refer to http://www.apple.com/quicktime/download/";
tag_summary = "The host is running QuickTime Player and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801680");
  script_version("$Revision: 8457 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-18 08:58:32 +0100 (Thu, 18 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-12-29 07:31:27 +0100 (Wed, 29 Dec 2010)");
  script_cve_id("CVE-2010-1508", "CVE-2010-0530", "CVE-2010-3800",
                "CVE-2010-3801", "CVE-2010-3802", "CVE-2010-4009");
  script_bugtraq_id(45236,45237,45239,45240,45241,45242);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Apple QuickTime Multiple vulnerabilities - Dec10 (Windows)");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT4447");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/3143");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce/2010/dec/msg00000.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
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

## Get the version from KB
quickVer = get_kb_item("QuickTime/Win/Ver");
if(!quickVer){
  exit(0);
}

## Check for QuickTime Playe Version less than 7.6.9
if(version_is_less(version:quickVer, test_version:"7.6.9")){
  security_message(0);
}
