###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wireshark_dect_bof_vuln_macosx.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Wireshark DECT Buffer Overflow Vulnerability (Mac OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation could allow attackers to cause buffer overflow and
  execute arbitrary code on the system.
  Impact Level: System/Application";
tag_affected = "Wireshark version 1.4.0 through 1.4.4";
tag_insight = "The flaw is due to error in the 'DECT' dissector when processing
  malformed data, which could allow code execution via malformed packets or
  a malicious PCAP file.";
tag_solution = "Upgrade to the Wireshark version 1.4.5 or later,
  For updates refer to http://www.wireshark.org/download.html";
tag_summary = "This host is installed with Wireshark and is prone to buffer
  overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903023");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2011-1591");
  script_bugtraq_id(47392);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-04-25 18:34:41 +0530 (Wed, 25 Apr 2012)");
  script_name("Wireshark DECT Buffer Overflow Vulnerability (Mac OS X)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/44172");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/66834");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/1022");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2011-06.html");

  script_copyright("Copyright (C) 2012 SecPod");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
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
wiresharkVer = "";

## Get the version from KB
wiresharkVer = get_kb_item("Wireshark/MacOSX/Version");
if(!wiresharkVer){
  exit(0);
}

## Check for Wireshark Version
if(version_in_range(version:wiresharkVer, test_version:"1.4.0", test_version2:"1.4.4")){
  security_message(0);
}
