###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_dos_vuln02_september14_win.nasl 6637 2017-07-10 09:58:13Z teissa $
#
# Wireshark DOS Vulnerability-02 Sep14 (Windows)
#
# Authors:
# Deepmala <kdeepmala@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.804912");
  script_version("$Revision: 6637 $");
  script_cve_id("CVE-2014-6426", "CVE-2014-6425");
  script_bugtraq_id(69866, 69863);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 11:58:13 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-09-24 14:29:16 +0530 (Wed, 24 Sep 2014)");

  script_name("Wireshark DOS Vulnerability-02 Sep14 (Windows)");

  script_tag(name: "summary" , value:"This host is installed with Wireshark
  and is prone to denial of service vulnerability.");

  script_tag(name: "vuldetect" , value: "Get the installed version with the
  help of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value: "Flaws are due to,
  - Error in the get_quoted_string and get_unquoted_string functions
    in epan/dissectors/packet-cups.c in the CUPS dissector.
  - The dissect_hip_tlv function in epan/dissectors/packet-hip.c
    in the HIP dissector does not properly handle a NULL tree.");

  script_tag(name: "impact" , value: "Successful exploitation will allow
  attackers to cause denial of service attack.

  Impact Level: Application");

  script_tag(name: "affected" , value: "Wireshark version 1.12.x before 1.12.1 on Windows");

  script_tag(name: "solution" , value: "Upgrade to Wireshark version 1.12.1 or later,
  For updates refer to https://www.wireshark.org");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://www.wireshark.org/security/wnpa-sec-2014-15.html");
  script_xref(name : "URL" , value : "https://www.wireshark.org/security/wnpa-sec-2014-16.html");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

## Variable Initialization
version = "";

## Get the version
if(!version = get_app_version(cpe:CPE)){
  exit(0);
}

## Check the vulnerable version is 1.12.x before 1.12.1
if(version_is_equal(version:version, test_version:"1.12.0"))
{
  security_message(0);
  exit(0);
}
