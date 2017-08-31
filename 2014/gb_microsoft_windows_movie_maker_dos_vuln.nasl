###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_microsoft_windows_movie_maker_dos_vuln.nasl 2014-01-02 17:01:32Z jan$
#
# Microsoft Windows Movie Maker Denial of Service Vulnerability
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804182";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6637 $");
  script_cve_id("CVE-2013-4858");
  script_bugtraq_id(61334);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 11:58:13 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-01-02 15:02:10 +0530 (Thu, 02 Jan 2014)");
  script_name("Microsoft Windows Movie Maker Denial of Service Vulnerability");

  tag_summary =
"This host is installed with Microsoft Windows Movie Maker and is prone to
denial of service vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"The flaw is due to some unspecified error triggered when a user opens a
malformed 'WAV' file.";

  tag_impact =
"Successful exploitation will allow a local attacker to crash the affected
application and cause denial of service.

Impact Level: Application";

  tag_affected =
"Microsoft Windows Movie Maker version 2.1.4026.0 on Windows XP SP3";

  tag_solution =
"No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/122473/");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");


## Check for OS and Service Pack
if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 3" >!< SP)
  {
    exit(0);
  }
}

## Confirm Application
if(!registry_key_exists(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                            "\App Paths\moviemk.exe")){
  exit(0);
}

## Get Program Files Dir Path
moviemkPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                                  item:"ProgramFilesDir");
if(!moviemkPath){
  exit(0);
}

## Get moviemk.exe Path
moviemkPath = moviemkPath + "\Movie Maker";

## Get Version from moviemk.exe file
moviemkVer=fetch_file_version(sysPath: moviemkPath, file_name:"moviemk.exe");
if(!moviemkVer){
  exit(0);
}

## Check for moviemk.exe version
if(version_is_equal(version:moviemkVer,test_version:"2.1.4026.0"))
{
  security_message(0);
  exit(0);
}

