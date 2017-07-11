###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bullguard_av_auth_bypass_vuln_may15.nasl 6229 2017-05-29 09:04:10Z teissa $
#
# BullGuard Antivirus Authentication Bypass Vulnerability
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

CPE = "cpe:/a:bullguard:antivirus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805623");
  script_version("$Revision: 6229 $");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-05-29 11:04:10 +0200 (Mon, 29 May 2017) $");
  script_tag(name:"creation_date", value:"2015-05-20 12:26:57 +0530 (Wed, 20 May 2015)");
  script_name("BullGuard Antivirus Authentication Bypass Vulnerability");

  script_tag(name:"summary", value:"This host is installed with BullGuard
  Antivirus and is prone to authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists due to poor password-based
  authentication of the implemented password protection in the management
  console.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  attacker to bypass implemented password protection mechanism in the applications
  management console.

  Impact Level: Application");

  script_tag(name:"affected", value:"BullGuard Antivirus version 15.0.297");

  script_tag(name:"solution", value:"No solution or patch was made available
  for at least one year since disclosure of this vulnerability. Likely none
  will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the
  product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/131811");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_bullguard_antivirus_detect.nasl");
  script_mandatory_keys("BullGuard/AntiVirus/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
bullVer = "";

## Get version
if(!bullVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Grep for vulnerable version
if(version_is_equal(version:bullVer, test_version:"15.0.297"))
{
  report = 'Installed version: ' + bullVer + '\n' +
           'Fixed version:     ' + 'WillNotFix' + '\n';
  security_message(data:report);
  exit(0);
}
