###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_mult_vuln02_dec12_macosx.nasl 3058 2016-04-14 10:45:44Z benallard $
#
# Wireshark Multiple Vulnerabilities-02 Dec 2012 (Mac OS X)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary code
  in the context of the application, crash affected application or to consume
  excessive CPU resources.
  Impact Level: System/Application";
tag_affected = "Wireshark 1.8.x before 1.8.2 on Mac OS X";
tag_insight = "The flaws are due to
  - An error within the pcap-ng file parser, Ixia IxVeriWave file parser and
    ERF dissector can be exploited to cause a buffer overflow.
  - An error within the MongoDB dissector can be exploited to trigger an
    infinite loop and consume excessive CPU resources.";
tag_solution = "Upgrade to the Wireshark version 1.8.2 or later,
  For updates refer to http://www.wireshark.org/download";
tag_summary = "This host is installed with Wireshark and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(803135);
  script_version("$Revision: 3058 $");
  script_cve_id("CVE-2012-4295", "CVE-2012-4294", "CVE-2012-4287");
  script_bugtraq_id(55035);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2016-04-14 12:45:44 +0200 (Thu, 14 Apr 2016) $");
  script_tag(name:"creation_date", value:"2012-12-28 14:58:22 +0530 (Fri, 28 Dec 2012)");
  script_name("Wireshark Multiple Vulnerabilities-02 Dec 2012 (Mac OS X)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50276/");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1027404");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2012-25.html");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2012-16.html");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2012-14.html");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2012-24.html");

  script_summary("Check for the version of Wireshark on Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
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

sharkVer = get_kb_item("Wireshark/MacOSX/Version");
if(!sharkVer){
  exit(0);
}

## Check for vulnerable Wireshark versions
if(version_in_range(version:sharkVer, test_version:"1.8.0", test_version2:"1.8.1")) {
  security_message(0);
}
