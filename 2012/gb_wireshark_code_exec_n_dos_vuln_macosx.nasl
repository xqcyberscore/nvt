###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_code_exec_n_dos_vuln_macosx.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Wireshark Code Execution and Denial of Service Vulnerabilities (Mac OS X)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_impact = "Successful exploitation will allow the attacker to execute arbitrary script
  in the context of the affected application and denial of service condition.
  Impact Level: System/Application";
tag_affected = "Wireshark versions 1.4.x before 1.4.9 and 1.6.x before 1.6.2 on Mac OS X";
tag_insight = "The flaws are due to
  - An unspecified error related to Lua scripts, which allows local users to
    gain privileges via a Trojan horse Lua script in an unspecified directory.
  - An error in 'IKEv1' protocol dissector and 'proto_tree_add_item()', when
    add more than 1000000 items to a proto_tree, that will cause a denial of
    service.";
tag_solution = "Upgrade to the Wireshark version 1.4.9, 1.6.2 or later,
  For updates refer to http://www.wireshark.org/download";
tag_summary = "This host is installed with Wireshark and is prone to code
  execution and denial of service vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802626");
  script_version("$Revision: 9352 $");
  script_bugtraq_id(49528, 49377);
  script_cve_id("CVE-2011-3360", "CVE-2011-3266");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-05-02 12:12:12 +0530 (Wed, 02 May 2012)");
  script_name("Wireshark Code Execution and Denial of Service Vulnerabilities (Mac OS X)");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2011-15.html");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2011-13.html");
  script_xref(name : "URL" , value : "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=6136");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
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

## Get version from KB
sharkVer = get_kb_item("Wireshark/MacOSX/Version");
if(!sharkVer){
  exit(0);
}

## Check for vulnerable Wireshark versions
if(version_in_range (version:sharkVer, test_version:"1.6.0", test_version2:"1.6.1") ||
   version_in_range (version:sharkVer, test_version:"1.4.0", test_version2:"1.4.8")) {
  security_message(0);
}
