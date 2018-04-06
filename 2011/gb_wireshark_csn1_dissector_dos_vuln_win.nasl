###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_csn1_dissector_dos_vuln_win.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Wireshark CSN.1 Dissector Denial of Service Vulnerability (Windows)
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

tag_impact = "Successful exploitation could allow attackers to cause a denial of service via
  via a malformed packet.
  Impact Level: Application";
tag_affected = "Wireshark version 1.6.x before 1.6.3";
tag_insight = "The flaw is due to an error in csnStreamDissector function in
  epan/dissectors/packet-csn1.c in the CSN.1 dissector, which fails to
  initialize a certain variable.";
tag_solution = "Upgrade to the Wireshark version 1.6.3 or later,
  For updates refer to http://www.wireshark.org/download.html";
tag_summary = "The host is installed with Wireshark and is prone to denial of
  service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802503");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-11-08 11:55:17 +0200 (Tue, 08 Nov 2011)");
  script_cve_id("CVE-2011-4100");
  script_bugtraq_id(50479);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Wireshark CSN.1 Dissector Denial of Service Vulnerability (Windows)");


  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_require_keys("Wireshark/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=750643");
  script_xref(name : "URL" , value : "http://openwall.com/lists/oss-security/2011/11/01/9");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2011-17.html");
  script_xref(name : "URL" , value : "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=6351");
  script_xref(name : "URL" , value : "http://anonsvn.wireshark.org/viewvc?view=revision&revision=39140");
  exit(0);
}


include("version_func.inc");

## Get the version from KB
wiresharkVer = get_kb_item("Wireshark/Win/Ver");
if(!wiresharkVer){
  exit(0);
}

## Check for Wireshark Version
if(version_in_range(version:wiresharkVer, test_version:"1.6.0", test_version2:"1.6.2")){
  security_message(0);
}
