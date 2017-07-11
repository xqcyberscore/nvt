###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dell_sonicwall_netextender_privilege_escalation_vuln.nasl 6243 2017-05-30 09:04:14Z teissa $
#
# Dell SonicWall NetExtender Privilege Escalation Vulnerability (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/o:dell:sonicwall_netextender";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806043");
  script_version("$Revision: 6243 $");
  script_cve_id("CVE-2015-4173");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-05-30 11:04:14 +0200 (Tue, 30 May 2017) $");
  script_tag(name:"creation_date", value:"2015-09-08 13:38:49 +0530 (Tue, 08 Sep 2015)");
  script_name("Dell SonicWall NetExtender Privilege Escalation Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is installed with Dell SonicWall
  NetExtender and is prone to privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help of
  detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists due to Unquoted Windows
  search path vulnerability in the autorun value upon installation of the
  product.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  privileged code execution upon administrative login.

  Impact Level: System/Application.");

  script_tag(name:"affected", value:"Dell SonicWall NetExtender version before
  7.5.227 and before 8.0.238 on Windows.");

  script_tag(name:"solution", value:"Upgrade to firmware version 7.5.227 or
  8.0.238 or later. For updates refer to http://www.sonicwall.com");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "https://packetstormsecurity.com/files/133302");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_dell_sonicwall_netextender_detect_win.nasl");
  script_mandatory_keys("Dell/SonicWall/NetExtender/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
netextVer = "";


## Get version
if(!netextVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:netextVer, test_version:"7.5.227") ||
   version_in_range(version:netextVer, test_version:"8.0", test_version2:"8.0.237"))
{
  report = 'Installed version: ' + netextVer + '\n' +
           'Fixed version:     7.5.227 or 8.0.238' + '\n';
  security_message(data:report );
  exit(0);
}
