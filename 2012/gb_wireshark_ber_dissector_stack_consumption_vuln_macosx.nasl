###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_ber_dissector_stack_consumption_vuln_macosx.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Wireshark BER Dissector Stack Consumption Vulnerability (Mac OS X)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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

tag_impact = "Successful exploitation will allow attackers to crash the application.
  Impact Level: Application";
tag_affected = "Wireshark version 1.4.x before 1.4.1 and 1.2.x before 1.2.12";
tag_insight = "The flaw is due to stack consumption error in the
  'dissect_ber_unknown()' function in 'epan/dissectors/packet-ber.c' in the
  BER dissector, which allows remote attackers to cause a denial of service
  (NULL pointer dereference and crash) via a long string in an unknown
  'ASN.1/BER' encoded packet.";
tag_solution = "Upgrade to Wireshark 1.4.1 or 1.2.12 or later.
  For updates refer to http://www.wireshark.org/download";
tag_summary = "This host is installed with Wireshark and is prone to stack
  consumption vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802845");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2010-3445");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-05-04 18:26:03 +0530 (Fri, 04 May 2012)");
  script_name("Wireshark BER Dissector Stack Consumption Vulnerability (Mac OS X)");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2010/10/12/1");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2010/10/01/10");
  script_xref(name : "URL" , value : "http://xorl.wordpress.com/2010/10/15/cve-2010-3445-wireshark-asn-1-ber-stack-overflow/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
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
sharkVer = "";

sharkVer = get_kb_item("Wireshark/MacOSX/Version");
if(!sharkVer){
  exit(0);
}

## Check version 1.4.0 or 1.2.0 through 1.2.11
if(version_is_equal(version:sharkVer, test_version:"1.4.0") ||
   version_in_range(version:sharkVer, test_version:"1.2.0", test_version2:"1.2.11")){
  security_message(0);
}
