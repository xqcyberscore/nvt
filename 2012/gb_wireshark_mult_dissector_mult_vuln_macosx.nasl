###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_mult_dissector_mult_vuln_macosx.nasl 8649 2018-02-03 12:16:43Z teissa $
#
# Wireshark LDP PPP and HSRP dissector Multiple Vulnerabilities (Mac OS X)
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

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  code in the context of the application, to crash the affected application,
  or to consume excessive CPU resources.
  Impact Level: System/Application";
tag_affected = "Wireshark versions 1.8.x prior to 1.8.3 on Mac OS X";
tag_insight = "Errors in the HSRP, PPP and LDP dissectors when processing certain
  packets can be exploited to cause an infinite loop and consume CPU
  resources or a buffer overflow.";
tag_solution = "Upgrade to the Wireshark version 1.8.3 or later,
  For updates refer to http://www.wireshark.org/download";
tag_summary = "This host is installed with Wireshark and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802982");
  script_version("$Revision: 8649 $");
  script_cve_id("CVE-2012-5237", "CVE-2012-5238", "CVE-2012-5240");
  script_bugtraq_id(55754);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-02-03 13:16:43 +0100 (Sat, 03 Feb 2018) $");
  script_tag(name:"creation_date", value:"2012-10-11 17:06:48 +0530 (Thu, 11 Oct 2012)");
  script_name("Wireshark LDP PPP and HSRP dissector Multiple Vulnerabilities (Mac OS X)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50843/");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2012-27.html");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2012-26.html");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2012-29.html");
  script_xref(name : "URL" , value : "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=7668");
  script_xref(name : "URL" , value : "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=7581");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_require_keys("Wireshark/MacOSX/Version");
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
sharkVer = "";

## Get version from KB
sharkVer = get_kb_item("Wireshark/MacOSX/Version");
if(!sharkVer){
  exit(0);
}

## Check for vulnerable Wireshark versions
if(version_in_range(version:sharkVer, test_version:"1.8.0", test_version2:"1.8.2")){
  security_message(0);
}
