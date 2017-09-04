###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_libpcap_dos_n_code_exec_vuln_win.nasl 7000 2017-08-24 11:51:46Z teissa $
#
# Wireshark 'Libpcap' Denial of Service and Code Execution Vulnerabilities (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804666");
  script_version("$Revision: 7000 $");
  script_cve_id("CVE-2014-4174");
  script_bugtraq_id(66755);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-08-24 13:51:46 +0200 (Thu, 24 Aug 2017) $");
  script_tag(name:"creation_date", value:"2014-07-07 10:20:48 +0530 (Mon, 07 Jul 2014)");
  script_name("Wireshark 'Libpcap' Denial of Service and Code Execution Vulnerabilities (Windows)");

  tag_summary =
"This host is installed with Wireshark and is prone to denial of service and
remote code execution vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Flaw is due to an unspecified error in 'wiretap/libpcap.c' within the libpcap
file parser.";

  tag_impact =
"Successful exploitation will allow attackers to cause a DoS (Denial of Service)
and compromise a vulnerable system.

Impact Level: System/Application";

  tag_affected =
"Wireshark version 1.10.x before 1.10.4 on Windows";

  tag_solution =
"Upgrade to Wireshark version 1.10.4 or later,
For updates refer to http://www.wireshark.org/download";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/57801");
  script_xref(name : "URL" , value : "https://www.hkcert.org/my_url/en/alert/14041102");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2014-05.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
sharkVer = "";

## Get version
if(!sharkVer = get_app_version(cpe:CPE)){
  exit(0);
}

# Check for vulnerable version
if(sharkVer  =~ "^(1\.10)")
{
  if(version_in_range(version:sharkVer, test_version:"1.10.0", test_version2:"1.10.3"))
  {
    security_message(0);
    exit(0);
  }
}
