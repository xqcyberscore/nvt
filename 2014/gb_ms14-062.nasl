###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms14-062.nasl 6715 2017-07-13 09:57:40Z teissa $
#
# Microsoft Windows Message Queuing Service Privilege Escalation Vulnerability (2993254)
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
  script_oid("1.3.6.1.4.1.25623.1.0.804492");
  script_version("$Revision: 6715 $");
  script_cve_id("CVE-2014-4971");
  script_bugtraq_id(68764);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-07-13 11:57:40 +0200 (Thu, 13 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-10-15 08:38:41 +0530 (Wed, 15 Oct 2014)");
  script_tag(name:"solution_type", value: "VendorFix");

  script_name("Microsoft Windows Message Queuing Service Privilege Escalation Vulnerability (2993254)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS14-062.");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"The flaw is due to an error when handling
  objects within the Message Queuing service, which can be exploited to elevate
  privileges by sending a specially crafted IOCTL request.");

  script_tag(name:"impact", value:"Successful exploitation could allow
  local users to gain escalated privileges.

  Impact Level: System");

  script_tag(name:"affected", value:"Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,
  https://technet.microsoft.com/library/security/MS14-062");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/60974/");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/MS14-062");
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
if(!sysPath){
  exit(0);
}

win32SysVer = fetch_file_version(sysPath, file_name:"system32\drivers\Mqac.sys");
if(!win32SysVer){
  exit(0);
}

## Windows 2003
if(hotfix_check_sp(win2003:3, win2003x64:3) > 0)
{
  ## Check for XML Core Services 3.0
  if(version_is_less(version:win32SysVer, test_version:"5.2.2008.5417")){
    security_message(0);
  }
  exit(0);
}
