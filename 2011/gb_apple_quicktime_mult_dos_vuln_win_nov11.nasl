###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_quicktime_mult_dos_vuln_win_nov11.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Apple QuickTime Multiple Denial of Service Vulnerabilities - (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code or
  cause a denial of service via crafted files.
  Impact Level: System/Application";
tag_affected = "QuickTime Player version prior to 7.7.1";
tag_insight = "The flaws are due to
  - A integer overflow while handling the PICT files and JPEG2000 encoded
    movie files.
  - A signedness issue existed in the handling of font tables embedded in
    QuickTime movie files.
  - A buffer overflow issue while handling FLIC files, FlashPix files and FLC
    and RLE encoded movie files.
  - A memory corruption issue, while handling of TKHD atoms in QuickTime
    movie files.";
tag_solution = "Upgrade to QuickTime Player version 7.7.1 or later,
  For updates refer to http://www.apple.com/quicktime/download/";
tag_summary = "The host is installed with Apple QuickTime and is prone to multiple
  denial of service vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802198");
  script_version("$Revision: 9351 $");
  script_cve_id("CVE-2011-3219", "CVE-2011-3220", "CVE-2011-3221", "CVE-2011-3218",
                "CVE-2011-3222", "CVE-2011-3223", "CVE-2011-3228", "CVE-2011-3247",
                "CVE-2011-3248", "CVE-2011-3249", "CVE-2011-3250", "CVE-2011-3251",
                "CVE-2011-3428");
  script_bugtraq_id(50068, 50130, 50131, 50122, 50100, 50101, 50127, 50399, 50400,
                    50404, 50401, 50403);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-11-03 12:22:48 +0100 (Thu, 03 Nov 2011)");
  script_name("Apple QuickTime Multiple Denial of Service Vulnerabilities - (Windows)");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT5016");
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-11-314/");
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-11-315/");

  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
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

## Check for QuickTime Playe Version less than 7.7.1
if(version_is_less(version:quickVer, test_version:"7.7.1")){
  security_message(0);
}
