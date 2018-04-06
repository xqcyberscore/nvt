###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wireshark_ansi_map_dos_vuln_win.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Wireshark ANSI A MAP Files Denial of Service Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  Impact Level: Application.";
tag_affected = "Wireshark version 1.6.0
  Wireshark version 1.4.x through 1.4.7";
tag_insight = "The flaw is caused to an infinite loop was found in the way ANSI A Interface
  dissector of the Wireshark network traffic analyser processed certain ANSI A
  MAP capture files. If Wireshark read a malformed packet off a network or
  opened a malicious packet capture file, it could lead to denial of service.";
tag_solution = "Upgrade to Wireshark version 1.4.8 or 1.6.1 or later,
  For updates refer to http://www.wireshark.org/download.html";
tag_summary = "This host is installed with Wireshark and is prone to denial of
  service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902721");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-08-26 14:59:42 +0200 (Fri, 26 Aug 2011)");
  script_cve_id("CVE-2011-2698");
  script_bugtraq_id(49071);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Wireshark ANSI A MAP Files Denial of Service Vulnerability (Windows)");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_family("Denial of Service");
  script_require_keys("Wireshark/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45086");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2011/07/20/2");
  script_xref(name : "URL" , value : "http://anonsvn.wireshark.org/viewvc?view=revision&revision=37930");
  exit(0);
}


include("version_func.inc");

wireVer = get_kb_item("Wireshark/Win/Ver");
if(!wireVer){
  exit(0);
}

if(version_is_equal(version:wireVer, test_version:"1.6.0") ||
   version_in_range(version:wireVer, test_version:"1.4.0", test_version2:"1.4.7")){
  security_message(0);
}
