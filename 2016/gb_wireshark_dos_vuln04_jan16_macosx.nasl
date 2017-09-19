###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_dos_vuln04_jan16_macosx.nasl 7174 2017-09-18 11:48:08Z asteins $
#
# Wireshark Denial-of-Service Vulnerability January16 (Mac OS X)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806950");
  script_version("$Revision: 7174 $");
  script_cve_id("CVE-2015-3182");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-09-18 13:48:08 +0200 (Mon, 18 Sep 2017) $");
  script_tag(name:"creation_date", value:"2016-01-11 11:59:19 +0530 (Mon, 11 Jan 2016)");
  script_name("Wireshark Denial-of-Service Vulnerability January16 (Mac OS X)");

  script_tag(name: "summary" , value:"This host is installed with Wireshark
  and is prone to multiple denial of service vulnerabilities.");

  script_tag(name: "vuldetect" , value: "Get the installed version with the
  help of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value: "The flaw exists due to
  - 'epan/dissectors/packet-dec-dnart.c' script in the
  DECnet NSP/RT dissector mishandles a certain strdup return value.");

  script_tag(name: "impact" , value: "Successful exploitation will allow remote
  attackers to conduct denial of service attack.

  Impact Level: Application");

  script_tag(name: "affected" , value: "Wireshark version 1.10.12 through 1.10.14 on MAC OS X");

  script_tag(name: "solution" , value: "No solution or patch was made available
  for at least one year since disclosure of this vulnerability. Likely none will
  be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another
  one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name : "URL" , value : "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=1219409");

  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

## Check the vulnerable version 1.10.12 through 1.10.14
if(version_in_range(version:wirversion, test_version:"1.10.12", test_version2:"1.10.14"))
{
  report = 'Installed Version: ' + wirversion + '\n' +
           'Fixed Version:   NoneAvailable \n';
  security_message(data:report);
  exit(0);
}
