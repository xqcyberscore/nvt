###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_mult_vuln_win_apr12.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Wireshark Multiple Vulnerabilities - April 12 (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary code
  or cause a denial of service.
  Impact Level: Application";
tag_affected = "Wireshark versions 1.4.x before 1.4.11 and 1.6.x before 1.6.5 on Windows";
tag_insight = "The flaws are due to
  - NULL pointer dereference errors when reading certain packet information
    can be exploited to cause a crash.
  - An error within the RLC dissector can be exploited to cause a buffer
    overflow via a specially crafted RLC packet capture file.
  - An error within the 'lanalyzer_read()' function (wiretap/lanalyzer.c) when
    parsing LANalyzer files can be exploited to cause a heap-based buffer
    underflow.";
tag_solution = "Upgrade to the Wireshark version 1.4.11, 1.6.5 or later,
  For updates refer to http://www.wireshark.org/download";
tag_summary = "This host is installed with Wireshark and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802761");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-0068", "CVE-2012-0067", "CVE-2012-0066", "CVE-2012-0043",
                "CVE-2012-0042", "CVE-2012-0041");
  script_bugtraq_id(51710, 51368);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-04-23 18:33:55 +0530 (Mon, 23 Apr 2012)");
  script_name("Wireshark Multiple Vulnerabilities - April 12 (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47494/");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2012-01.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_require_keys("Wireshark/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

## Variable Initialization
sharkVer = "";

## Get version from KB
sharkVer = get_kb_item("Wireshark/Win/Ver");
if(!sharkVer){
  exit(0);
}

## Check for vulnerable Wireshark versions
if(version_in_range(version:sharkVer, test_version:"1.4.0", test_version2:"1.4.10") ||
   version_in_range(version:sharkVer, test_version:"1.6.0", test_version2:"1.6.4")) {
  security_message(0);
}
