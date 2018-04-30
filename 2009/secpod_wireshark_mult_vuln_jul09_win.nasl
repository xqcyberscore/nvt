###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wireshark_mult_vuln_jul09_win.nasl 9657 2018-04-27 10:38:29Z cfischer $
#
# Wireshark Multiple Vulnerabilities - July09 (Windows)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900590");
  script_version("$Revision: 9657 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-27 12:38:29 +0200 (Fri, 27 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-07-22 21:36:53 +0200 (Wed, 22 Jul 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-2559", "CVE-2009-2560", "CVE-2009-2561");
  script_bugtraq_id(35748);
  script_name("Wireshark Multiple Vulnerabilities - July09 (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35884");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1970");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2009-04.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_require_keys("Wireshark/Win/Ver");
  script_tag(name : "impact" , value : "Successful exploitation could result in denial of service condition.
  Impact Level: Application");
  script_tag(name : "affected" , value : "Wireshark version 1.2.0 on Windows");
  script_tag(name : "insight" , value : "- An array index error in the IPMI dissector may lead to buffer overflow via
    unspecified vectors.
  - Multiple unspecified vulnerabilities in the Bluetooth L2CAP, MIOP or sFlow
    dissectors and RADIUS which can be exploited via specially crafted network
    packets.");
  script_tag(name : "solution" , value : "Upgrade to Wireshark 1.2.1 or later.
  http://www.wireshark.org/download.html");
  script_tag(name : "summary" , value : "This host is installed with Wireshark and is prone to multiple
  vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

sharkVer = get_kb_item("Wireshark/Win/Ver");
if(!sharkVer){
  exit(0);
}

if(version_is_equal(version:sharkVer, test_version:"1.2.0")){
  security_message(0);
}
