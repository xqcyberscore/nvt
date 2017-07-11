###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_kb3203383.nasl 6419 2017-06-23 12:48:13Z santu $
#
# Microsoft Office Remote Code Execution Vulnerability (KB3203383)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811212");
  script_version("$Revision: 6419 $");
  script_cve_id("CVE-2017-8510");
  script_bugtraq_id(98813);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-06-23 14:48:13 +0200 (Fri, 23 Jun 2017) $");
  script_tag(name:"creation_date", value:"2017-06-21 15:13:34 +0530 (Wed, 21 Jun 2017)");
  script_name("Microsoft Office Remote Code Execution Vulnerability (KB3203383)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB3178667");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"The flaw exists due to an error in Microsoft
  Office software when the Office software fails to properly handle objects in
  memory. ");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to use a specially crafted file and perform actions in the security context of
  the current user. The file could then, for example, take actions on behalf of
  the logged-on user with the same permissions as the current user.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"Microsoft Office 2016");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,
  https://support.microsoft.com/en-us/help/3203383");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/help/3203383");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variable initialization
officeVer = "";
offPath = "";
offdllVer = "";

## Check for office 2016
officeVer = get_kb_item("MS/Office/Ver");
if(!officeVer || !(officeVer =~ "^(16\.)")){
  exit(0);
}

## Check Program File Directory
path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                       item:"ProgramFilesDir");
if(!path){
  exit(0);
}

##For x86 based installation
##To Do, Check path for 64bit installation and update path here
offPath = path + "\Microsoft Office\root\VFS\ProgramFilesCommonX86\Microsoft Shared\GRPHFLT";

## Get Version from epsimp32.flt
offdllVer = fetch_file_version(sysPath:offPath, file_name:"epsimp32.flt");
if(!offdllVer){
  exit(0);
}

##Check for vulnerable version
if(offdllVer =~ "^(2012\.1600\.)" && version_is_less(version:offdllVer, test_version:"2012.1600.8201.1003"))
{
  report = 'File checked:     ' + offPath + "\epsimp32.flt" + '\n' +
           'File version:     ' + offdllVer  + '\n' +
           'Vulnerable range: ' + "2012.1600.0.0 - 2012.1600.8201.1002" + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
