###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms14-070.nasl 6692 2017-07-12 09:57:43Z teissa $
#
# Microsoft Windows TCP/IP Privilege Elevation Vulnerability (2989935)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805010");
  script_version("$Revision: 6692 $");
  script_cve_id("CVE-2014-4076");
  script_bugtraq_id(70976);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:57:43 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-11-12 08:19:24 +0530 (Wed, 12 Nov 2014)");
  script_name("Microsoft Windows TCP/IP Privilege Elevation Vulnerability (2989935)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS14-070.");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified error in
  the tcpip.sys and tcpip6.sys drivers when processing certain IOCTL.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to  execute arbitrary code.

  Impact Level: System");

  script_tag(name:"affected", value:"Microsoft Windows 2003 x32/x64 Edition
  Service Pack 2 and prior");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link, https://technet.microsoft.com/library/security/MS14-070");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/59881");
  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/2989935");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/MS14-070");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variables Initialization
sysPath = "";
win32SysVer="";

## Check for OS and Service Pack
if(hotfix_check_sp(win2003:3, win2003x64:3) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

win32SysVer = fetch_file_version(sysPath, file_name:"system32\drivers\tcpip.sys");
if(!win32SysVer){
  exit(0);
}

##Windows Server 2003
if(hotfix_check_sp(win2003x64:3,win2003:3) > 0)
{
  ## Check for Win32k.sys version
  if(version_is_less(version:win32SysVer, test_version:"5.2.3790.5440")){
    security_message(0);
  }
  exit(0);
}
