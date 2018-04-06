###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_ansi_map_dos_vuln_macosx.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Wireshark ANSI A MAP Files Denial of Service Vulnerability (Mac OS X)
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

tag_impact = "Successful exploitation allows attackers to crash an affected application,
  denying service to legitimate users.
  Impact Level: Application";
tag_affected = "Wireshark version 1.6.0
  Wireshark version 1.4.x to 1.4.7 on Mac OS X";
tag_insight = "The flaw is caused to an infinite loop was found in the way ANSI A interface
  dissector of the Wireshark network traffic analyzer processed certain ANSI A
  MAP capture files. If Wireshark read a malformed packet off a network or
  opened a malicious packet capture file, it could lead to denial of service.";
tag_solution = "Upgrade to Wireshark version 1.4.8 or 1.6.1 or later,
  For updates refer to http://www.wireshark.org/download.html";
tag_summary = "This host is installed with Wireshark and is prone to denial of
  service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802766");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2011-2698");
  script_bugtraq_id(49071);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-05-02 16:03:18 +0530 (Wed, 02 May 2012)");
  script_name("Wireshark ANSI A MAP Files Denial of Service Vulnerability (Mac OS X)");


  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_family("Denial of Service");
  script_require_keys("Wireshark/MacOSX/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45086");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2011/07/20/2");
  script_xref(name : "URL" , value : "http://anonsvn.wireshark.org/viewvc?view=revision&revision=37930");
  exit(0);
}


include("version_func.inc");

## Variable Initialization
wireVer = "";

wireVer = get_kb_item("Wireshark/MacOSX/Version");
if(!wireVer){
  exit(0);
}

if(version_is_equal(version:wireVer, test_version:"1.6.0") ||
   version_in_range(version:wireVer, test_version:"1.4.0", test_version2:"1.4.7")){
  security_message(0);
}
