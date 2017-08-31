###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_kb3203467.nasl 6479 2017-06-29 07:59:07Z teissa $
#
# Microsoft Outlook 2010 Service Pack 2 Multiple Vulnerabilities (KB3203467)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.811151");
  script_version("$Revision: 6479 $");
  script_cve_id("CVE-2017-8506", "CVE-2017-8507", "CVE-2017-8508");
  script_bugtraq_id(98811, 98827, 98828);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-06-29 09:59:07 +0200 (Thu, 29 Jun 2017) $");
  script_tag(name:"creation_date", value:"2017-06-14 08:25:15 +0530 (Wed, 14 Jun 2017)");
  script_name("Microsoft Outlook 2010 Service Pack 2 Multiple Vulnerabilities (KB3203467)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB3203467");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"Multiple flaw exists,

  - When Office improperly validates input before loading dynamic link library
    (DLL) files.

  - The way that Microsoft Outlook parses specially crafted email messages.
 
  - When it improperly handles the parsing of file formats. ");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an attacker to take control of an affected system. 

  Impact Level: System/Application");

  script_tag(name:"affected", value:"Microsoft Outlook 2010 Service Pack 2");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,
  https://support.microsoft.com/en-us/help/3203467");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/help/3203467");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Outlook/Version");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");


## Variable Initialization
outlookVer = "";
outlookFile = "";

## Check for Office outlook Version
outlookVer = get_kb_item("SMB/Office/Outlook/Version");

## Check for Microsoft Outlook 2010
if(!outlookVer || !(outlookVer =~ "^14\.")){
  exit(0);
}

## Get Office outlook Path
outlookFile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                              "\App Paths\OUTLOOK.EXE", item:"Path");
if(!outlookFile){
  exit(0);
}

## Get Office outlook Version
outlookVer = fetch_file_version(sysPath:outlookFile, file_name:"outlook.exe");
if(!outlookVer){
  exit(0);
}

## Check for vulnerable versions
if(version_in_range(version:outlookVer, test_version:"14.0", test_version2:"14.0.7182.4999"))
{
  report = 'File checked:     ' +  outlookFile + "\outlook.exe" + '\n' +
           'File version:     ' +  outlookVer  + '\n' +
           'Vulnerable range:  14.0 - 14.0.7182.4999'+ '\n' ;
  security_message(data:report);
  exit(0);
}

