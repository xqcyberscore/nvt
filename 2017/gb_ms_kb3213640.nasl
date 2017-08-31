###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_kb3213640.nasl 6757 2017-07-19 05:57:31Z cfischer $
#
# Microsoft Office 2007 Service Pack 3 Remote Code Execution Vulnerability (KB3213640)
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
  script_oid("1.3.6.1.4.1.25623.1.0.811232");
  script_version("$Revision: 6757 $");
  script_cve_id("CVE-2017-8570");
  script_bugtraq_id(99445);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-07-19 07:57:31 +0200 (Wed, 19 Jul 2017) $");
  script_tag(name:"creation_date", value:"2017-07-12 12:22:24 +0530 (Wed, 12 Jul 2017)");
  script_name("Microsoft Office 2007 Service Pack 3 Remote Code Execution Vulnerability (KB3213640)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB3213640");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"The flaw exists due to an error in Microsoft
  Office software when it fails to properly handle objects in memory. ");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to use a specially crafted file to perform actions in the security context of
  the current user. 

  Impact Level: System/Application");

  script_tag(name:"affected", value:"Microsoft Office 2007 Service Pack 3");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,
  https://support.microsoft.com/en-us/help/3213640");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/help/3213640");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");


## variable Initialization
commonpath = "";
officeVer = "";
offPath = "";
offexeVer = "";

## MS Office Version
officeVer = get_kb_item("MS/Office/Ver");
if(!officeVer){
  exit(0);
}

## Get Common File Path
commonpath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                            item:"CommonFilesDir");
if(!commonpath){
  exit(0);
}

if(officeVer =~ "^(12\.)")
{
  ##Office Path
  offPath = commonpath + "\Microsoft Shared\Office12";

  ## Get Version from Mso.dll
  offexeVer = fetch_file_version(sysPath:offPath, file_name:"Mso.dll");

  ##Check for vulnerable Microsoft Office versions
  if(offexeVer && version_in_range(version:offexeVer, test_version:"12.0", test_version2:"12.0.6772.4999"))
  {
    report = 'File checked:     ' + offPath + "\Mso.dll" + '\n' +
             'File version:     ' + offexeVer  + '\n' +
             'Vulnerable range: ' + '12.0 - 12.0.6772.4999' + '\n' ;
    security_message(data:report);
    exit(0);
  }
}
exit(0);
