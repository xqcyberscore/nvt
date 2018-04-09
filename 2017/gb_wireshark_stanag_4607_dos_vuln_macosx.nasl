###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_stanag_4607_dos_vuln_macosx.nasl 9381 2018-04-06 11:21:01Z cfischer $
#
# Wireshark 'STANAG 4607' Capture File Denial of Service Vulnerability (Mac OS X)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.810700");
  script_version("$Revision: 9381 $");
  script_cve_id("CVE-2017-6014");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 13:21:01 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2017-02-21 15:26:53 +0530 (Tue, 21 Feb 2017)");
  script_name("Wireshark 'STANAG 4607' Capture File Denial of Service Vulnerability (Mac OS X)");

  script_tag(name: "summary" , value:"This host is installed with Wireshark
  and is prone to denial of service vulnerability.");

  script_tag(name: "vuldetect" , value: "Get the installed version with the
  help of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw is due to a crafted or
  malformed STANAG 4607 capture file will cause an infinite loop and memory
  exhaustion. If the packet size field in a packet header is null, the offset
  to read from will not advance, causing continuous attempts to read the same
  zero length packet. This will quickly exhaust all system memory."); 
   

  script_tag(name: "impact" , value: "Successful exploitation will allow remote
  attackers to cause the application to enter an infinite loop and consume 
  excessive CPU resources, resulting in denial-of-service conditions.

  Impact Level: Application");

  script_tag(name: "affected" , value: "Wireshark versions 2.2.4 and prior
  on Mac OS X");

  script_tag(name: "solution" , value: "Update to Wireshark 2.2.5 or later.
  For updates refer to https://www.wireshark.org");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name : "URL" , value : "http://git.net/ml/general/2017-02/msg20415.html");
  script_xref(name : "URL" , value : "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=13416");
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

## Get the version
if(!wirversion = get_app_version(cpe:CPE)){
  exit(0);
}

## Check the vulnerable version
if(version_is_less_equal(version: wirversion, test_version:"2.2.4"))
{
  report = report_fixed_ver(installed_version:wirversion, fixed_version:"2.2.5");
  security_message(data:report);
  exit(0);
}
