###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_dos_vuln_may13_macosx.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Wireshark ASN.1 BER Dissector DoS Vulnerability - May 13 (Mac OS X)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
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

tag_impact = "Successful exploitation will allow remote attackers to cause denial of
  service by injecting a malformed packet.
  Impact Level: Application";

tag_affected = "Wireshark 1.6.x before 1.6.15 and 1.8.x before 1.8.7 on Mac OS X";
tag_insight = "- 'fragment_add_seq_common' function in epan/reassemble.c has an incorrect
    pointer dereference.
  - 'dissect_ber_choice' function in epan/dissectors/packet-ber.c does not
    properly initialize variables.";
tag_solution = "Upgrade to the Wireshark version 1.6.15 or 1.8.7 or later,
  For updates refer to http://www.wireshark.org/download";
tag_summary = "This host is installed with Wireshark and is prone to denial of
  service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803619");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-3557", "CVE-2013-3556");
  script_bugtraq_id(59997, 60021);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-05-28 13:52:52 +0530 (Tue, 28 May 2013)");
  script_name("Wireshark ASN.1 BER Dissector DoS Vulnerability - May 13 (Mac OS X)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/53425");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2013-25.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Version");
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
if(sharkVer && sharkVer=~ "^(1.6|1.8)")
{
  ## Check for vulnerable Wireshark versions
  if(version_in_range(version:sharkVer, test_version:"1.6.0", test_version2:"1.6.14") ||
     version_in_range(version:sharkVer, test_version:"1.8.0", test_version2:"1.8.6")){
    security_message(0);
    exit(0);
  }
}
