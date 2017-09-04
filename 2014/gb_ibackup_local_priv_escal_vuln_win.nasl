###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibackup_local_priv_escal_vuln_win.nasl 6995 2017-08-23 11:52:03Z teissa $
#
# iBackup Local Privilege Escalation Vulnerability (Windows)
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

CPE = "cpe:/a:pro_softnet_corporation:ibackup";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805200");
  script_version("$Revision: 6995 $");
  script_cve_id("CVE-2014-5507");
  script_bugtraq_id(70724);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-08-23 13:52:03 +0200 (Wed, 23 Aug 2017) $");
  script_tag(name:"creation_date", value:"2014-12-01 12:04:33 +0530 (Mon, 01 Dec 2014)");
  script_name("iBackup Local Privilege Escalation Vulnerability (Windows)");

  script_tag(name: "summary" , value:"The host is installed with iBackup and is
  prone to local privilege escalation vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Flaw exists as the program uses insecure
  permissions which can allow anyone to replace the ib_service.exe with an
  executable of their choice that is loaded on system or service restart.");

  script_tag(name: "impact" , value:"Successful exploitation will allow local
  attacker to gain elevated privileges.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"iBackup version 10.0.0.32 and prior on
  Windows.");

  script_tag(name: "solution" , value:"No solution or patch was made available
  for at least one year since disclosure of this vulnerability. Likely none will
  be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another
  one.");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/35040");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/128806/");

  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_ibackup_detect_win.nasl");
  script_mandatory_keys("iBackup/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
iBackupVer = "";

## Get version
if(!iBackupVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Grep for vulnerable version 10.0.0.32 and prior.
if(version_is_less_equal(version:iBackupVer, test_version:"10.0.0.32"))
{
  security_message(0);
  exit(0);
}
