###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_comodo_backup_auth_bypass_vuln_win.nasl 9381 2018-04-06 11:21:01Z cfischer $
#
# COMODO BackUp Authentication Bypass Vulnerability (Windows)
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
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

CPE = "cpe:/a:comodo:backup";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805344");
  script_version("$Revision: 9381 $");
  script_cve_id("CVE-2014-9633");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 13:21:01 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2015-03-06 11:49:43 +0530 (Fri, 06 Mar 2015)");
  script_tag(name:"qod_type", value:"registry");
  script_name("COMODO BackUp Authentication Bypass Vulnerability (Windows)");

  script_tag(name: "summary" , value:"The host is installed with COMODO BackUp
  and is prone to authentication bypass vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw exists due to the
  'bdisk.sys' driver allows remote attackers to gain privileges via a
  crafted device handle, which triggers a NULL pointer dereference");

  script_tag(name: "impact" , value:"Successful exploitation will allow
  remote attackers to bypass authentication and login to the remote server.

  Impact Level: Application");

  script_tag(name: "affected" , value:"COMODO BackUp version prior to
  4.4.1.23 on Windows.");

  script_tag(name: "solution" , value:"Upgrade to COMODO BackUp version
  4.4.1.23 or later, For updates refer to https://backup.comodo.com");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/35905");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/130094/Comodo-Backup-4.4.0.0-NULL-Pointer-Dereference.html");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_comodo_backup_detect_win.nasl");
  script_mandatory_keys("Comodo/BackUp/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
comodoVer = "";

## Get version
if(!comodoVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Grep for vulnerable version
if(version_is_less(version:comodoVer, test_version:"4.4.1.23"))
{
  report = 'Installed version: ' + comodoVer + '\n' +
           'Fixed version:     4.4.1.23'  + '\n';
  security_message(data:report);
  exit(0);
}
