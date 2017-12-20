###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_mult_vuln_win.nasl 8168 2017-12-19 07:30:15Z teissa $
#
# Wireshark Multiple Vulnerabilities (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

tag_impact = "Successful exploitation could allow attackers to cause a denial of
  service, execution of arbitrary code.
  Impact Level: Application";
tag_affected = "Wireshark version 1.2.0 to 1.2.9
  Wireshark version 0.10.8 to 1.0.14";
tag_insight = "Multiple flaws are due to error in 'sigcomp-udvm.c' and an
  off-by-one error, which could be exploited to execute arbitrary code.";
tag_solution = "Upgrade to the Wireshark version 1.0.15 or 1.2.10 or later,
  For updates refer to http://www.wireshark.org/download.html";
tag_summary = "The host is installed Wireshark and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801432");
  script_version("$Revision: 8168 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-19 08:30:15 +0100 (Tue, 19 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-08-19 10:23:11 +0200 (Thu, 19 Aug 2010)");
  script_cve_id("CVE-2010-2995");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Wireshark Multiple Vulnerabilities (win)");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2010-08.html");
  script_xref(name : "URL" , value : "http://www.wireshark.org/docs/relnotes/wireshark-1.2.10.html");

  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_wireshark_detect_win.nasl");
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

## Get the version from KB
wiresharkVer = get_kb_item("Wireshark/Win/Ver");
if(!wiresharkVer){
  exit(0);
}

## Check for Wireshark Version
if(version_in_range(version:wiresharkVer, test_version:"0.10.8", test_version2:"1.0.14")||
   version_in_range(version:wiresharkVer, test_version:"1.2.0", test_version2:"1.2.9")){
  security_message(0);
}
