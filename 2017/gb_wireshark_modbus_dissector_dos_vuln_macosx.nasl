###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_modbus_dissector_dos_vuln_macosx.nasl 7077 2017-09-07 13:41:54Z santu $
#
# Wireshark 'Modbus' Dissector DoS Vulnerability (Mac OS X)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.811800");
  script_version("$Revision: 7077 $");
  script_cve_id("CVE-2017-13764");
  script_bugtraq_id(100545);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-09-07 15:41:54 +0200 (Thu, 07 Sep 2017) $");
  script_tag(name:"creation_date", value:"2017-09-05 16:13:23 +0530 (Tue, 05 Sep 2017)");
  script_name("Wireshark 'Modbus' Dissector DoS Vulnerability (Mac OS X)");

  script_tag(name: "summary" , value:"This host is installed with Wireshark
  and is prone to denial of service vulnerability.");

  script_tag(name: "vuldetect" , value: "Get the installed version with the
  help of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value: "The flaw is due to a NULL pointer 
  dereference error in 'epan/dissectors/packet-mbtcp.c' script.");

  script_tag(name: "impact" , value: "Successful exploitation will allow 
  attackers to make Wireshark crash by injecting a malformed packet onto 
  the wire or by convincing someone to read a malformed packet trace file.

  Impact Level: Application");

  script_tag(name: "affected" , value: "Wireshark version 2.4.0 on Mac OS X.");

  script_tag(name: "solution" , value: "Upgrade to Wireshark version 2.4.1 or 
  later. For updates refer to https://www.wireshark.org");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name : "URL" , value : "https://www.wireshark.org/security/wnpa-sec-2017-40.html");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Version");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

## Variable Initialization
wirversion = "";
report = "";
fix = "";

## Get the version
if(!wirversion = get_app_version(cpe:CPE)){
  exit(0);
}

## Check the vulnerable version
if(wirversion == "2.4.0")
{
  report = report_fixed_ver(installed_version:wirversion, fixed_version:"2.4.1");
  security_message(data:report);
  exit(0);
}
