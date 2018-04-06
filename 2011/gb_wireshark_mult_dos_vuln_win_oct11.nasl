###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_mult_dos_vuln_win_oct11.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Wireshark Multiple Denial of Service Vulnerabilities (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_impact = "Successful exploitation will allow remote attackers to cause a denial of
  service.
  Impact Level: Application";
tag_affected = "Wireshark versions 1.6.x before 1.6.2.";
tag_insight = "- An error related to an uninitialised variable within the CSN.1 dissector
    can be exploited to cause a crash.
  - A buffer exception handling vulnerability exists that can allow denial of
    service attacks when processing certain malformed packets.
  - An error within the OpenSafety dissector can be exploited to cause a large
    loop and crash the application.";
tag_solution = "Upgrade to the Wireshark version 1.6.2 or later,
  For updates refer to http://www.wireshark.org/download";
tag_summary = "This host is installed with Wireshark and is prone to multiple
  denial of service vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802248");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-10-04 16:55:13 +0200 (Tue, 04 Oct 2011)");
  script_bugtraq_id(49521, 49522, 49524);
  script_cve_id("CVE-2011-3482", "CVE-2011-3483", "CVE-2011-3484");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Wireshark Multiple Denial of Service Vulnerabilities (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45927/");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2011-16.html");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2011-14.html");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2011-12.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
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

## Get version from KB
sharkVer = get_kb_item("Wireshark/Win/Ver");
if(!sharkVer){
  exit(0);
}

## Check for vulnerable Wireshark versions
if(version_in_range (version:sharkVer, test_version:"1.6.0", test_version2:"1.6.1")) {
  security_message(0);
}
