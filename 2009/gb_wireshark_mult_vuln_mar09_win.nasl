###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_mult_vuln_mar09_win.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Wireshark Denial of Service Vulnerability (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful attacks may cause the application to crash via unspecified
  attack vectors.
  Impact Level: Application";
tag_affected = "Wireshark version prior to 1.0.5 on Windows";
tag_insight = "Error in the WLCCP and SMTP dissector allows to exploit by triggering the
  execution into an infinite loop through specially crafted packets.";
tag_solution = "Upgrade to Wireshark 1.0.5
  http://www.wireshark.org/download.html";
tag_summary = "This host is installed with Wireshark and is prone to denial
  of service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800374");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-03-18 05:31:55 +0100 (Wed, 18 Mar 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-6472");
  script_name("Wireshark Denial of Service Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32840");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2008-07.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
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

sharkVer = get_kb_item("Wireshark/Win/Ver");
if(!sharkVer){
  exit(0);
}

# Grep for Wireshark version prior to 1.0.5
if(version_is_less(version:sharkVer, test_version:"1.0.5")){
  security_message(0);
}
