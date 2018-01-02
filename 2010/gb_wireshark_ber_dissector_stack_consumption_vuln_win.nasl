###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_ber_dissector_stack_consumption_vuln_win.nasl 8228 2017-12-22 07:29:52Z teissa $
#
# Wireshark BER Dissector Stack Consumption Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation will allow attackers to crash the application.
  Impact Level: Application";
tag_affected = "Wireshark version 1.4.x before 1.4.1 and 1.2.x before 1.2.12";
tag_insight = "The flaw is due to stack consumption  in the 'dissect_ber_unknown()'
  function in 'epan/dissectors/packet-ber.c' in the BER dissector, which allows
  remote attackers to cause a denial of service (NULL pointer dereference and
  crash) via a long string in an unknown 'ASN.1/BER' encoded packet.";
tag_solution = "Upgrade to Wireshark 1.4.1 or 1.2.12 or later,
  For updates refer to http://www.wireshark.org/download";
tag_summary = "This host is installed with Wireshark and is prone to stack
  consumption vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801553");
  script_version("$Revision: 8228 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-22 08:29:52 +0100 (Fri, 22 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-12-09 06:36:39 +0100 (Thu, 09 Dec 2010)");
  script_cve_id("CVE-2010-3445");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Wireshark BER Dissector Stack Consumption Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2010/10/12/1");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2010/10/01/10");
  script_xref(name : "URL" , value : "http://xorl.wordpress.com/2010/10/15/cve-2010-3445-wireshark-asn-1-ber-stack-overflow/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");
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

## Confirm Windows
sharkVer = get_kb_item("Wireshark/Win/Ver");
if(!sharkVer){
  exit(0);
}

## Check version 1.4.0 or 1.2.0 through 1.2.11
if(version_is_equal(version:sharkVer, test_version:"1.4.0") ||
   version_in_range(version:sharkVer, test_version:"1.2.0", test_version2:"1.2.11")){
  security_message(0);
}
