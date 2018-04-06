###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_mult_vuln01_feb13_win.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Wireshark Multiple Vulnerabilities(01) - Feb2013 (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation will allow remote attackers to crash affected
  application or to consume excessive CPU resources.
  Impact Level: Application";

tag_affected = "Wireshark 1.6.x before 1.6.13 and 1.8.x before 1.8.5 on Windows";
tag_insight = "The flaws are due to
  - Errors in the Bluetooth HCI, CSN.1, DCP-ETSI DOCSIS CM-STAUS, IEEE 802.3
    Slow Protocols, MPLS, R3, RTPS, SDP, and SIP dissectors can be exploited
    to trigger infinite loops and consume CPU resources via specially crafted
    packets.
  - An error in the CLNP, DTN, MS-MMC, DTLS , DCP-ETSI,  NTLMSSP and ROHC
    dissector when processing certain packets can be exploited to cause a
    crash via a specially crafted packet.
  - An error in the dissection engine when processing certain packets can be
    exploited to cause a crash via a specially crafted packet.";
tag_solution = "Upgrade to the Wireshark version 1.6.13, 1.8.5 or later,
  For updates refer to http://www.wireshark.org/download";
tag_summary = "This host is installed with Wireshark and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803165");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-1572", "CVE-2013-1573", "CVE-2013-1574", "CVE-2013-1575",
                "CVE-2013-1576", "CVE-2013-1577", "CVE-2013-1578", "CVE-2013-1579",
                "CVE-2013-1580", "CVE-2013-1581", "CVE-2013-1582", "CVE-2013-1583",
                "CVE-2013-1584", "CVE-2013-1585", "CVE-2013-1586", "CVE-2013-1587",
                "CVE-2013-1588", "CVE-2013-1589", "CVE-2013-1590");
  script_bugtraq_id(57616);
  script_tag(name:"cvss_base", value:"2.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-02-04 19:32:22 +0530 (Mon, 04 Feb 2013)");
  script_name("Wireshark Multiple Vulnerabilities(01) - Feb2013 (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51968");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2013-01.html");
  script_xref(name : "URL" , value : "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8037");
  script_xref(name : "URL" , value : "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8038");
  script_xref(name : "URL" , value : "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8040");
  script_xref(name : "URL" , value : "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8041");
  script_xref(name : "URL" , value : "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8042");
  script_xref(name : "URL" , value : "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8043");
  script_xref(name : "URL" , value : "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8198");
  script_xref(name : "URL" , value : "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8222");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_require_keys("Wireshark/Win/Ver");
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
sharkVer = "";

## Get version from KB
sharkVer = get_kb_item("Wireshark/Win/Ver");
if(!sharkVer && !(sharkVer =~ "^1")){
  exit(0);
}

## Check for vulnerable Wireshark versions
if(version_in_range(version:sharkVer, test_version:"1.8.0", test_version2:"1.8.4") ||
   version_in_range(version:sharkVer, test_version:"1.6.0", test_version2:"1.6.12")) {
  security_message(0);
}
