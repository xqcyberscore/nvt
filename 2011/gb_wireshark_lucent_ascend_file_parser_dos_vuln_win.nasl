###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_lucent_ascend_file_parser_dos_vuln_win.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Wireshark Lucent/Ascend File Parser Denial of Service Vulnerability (Windows)
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
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

tag_impact = "Successful exploitation allows attackers to cause the application to enter
  into an infinite loop and crash it.
  Impact Level: Application.";
tag_affected = "Wireshark version 1.2.0 to 1.2.17, 1.4.0 to 1.4.7 and 1.6.0";
tag_insight = "The flaw is due to an error in Lucent/Ascend file parser when
  processing malicious packets.";
tag_solution = "Upgrade to Wireshark 1.2.18 or later
  For updates refer to http://www.wireshark.org/download.html";
tag_summary = "This host is installed with Wireshark and is prone to denial of
  service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802308");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-07-14 13:16:44 +0200 (Thu, 14 Jul 2011)");
  script_cve_id("CVE-2011-2597");
  script_bugtraq_id(48506);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Wireshark Lucent/Ascend File Parser Denial of Service Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45086");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/68335");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2011-09.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
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
  exit(0);
}


include("version_func.inc");

wireVer = get_kb_item("Wireshark/Win/Ver");
if(!wireVer){
  exit(0);
}

if(version_in_range(version:wireVer, test_version:"1.2.0", test_version2:"1.2.17") ||
   version_in_range(version:wireVer, test_version:"1.4.0", test_version2:"1.4.7") ||
   version_is_equal(version:wireVer, test_version:"1.6.0")){
  security_message(0);
}
