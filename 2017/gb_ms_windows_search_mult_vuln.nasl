###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_windows_search_mult_vuln.nasl 6717 2017-07-13 12:31:56Z santu $
#
# Microsoft Windows Search Multiple Vulnerabilites (KB4024402)
#
# Authors:
# Rinu <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.810907");
  script_version("$Revision: 6717 $");
  script_cve_id("CVE-2017-8543", "CVE-2017-8544");
  script_bugtraq_id(98824, 98826);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-07-13 14:31:56 +0200 (Thu, 13 Jul 2017) $");
  script_tag(name:"creation_date", value:"2017-07-05 16:51:57 +0530 (Wed, 05 Jul 2017)");
  script_name("Microsoft Windows Search Multiple Vulnerabilites (KB4024402)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4024402");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"Multiple flaw exists when Windows Search 
  improperly handles objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an attacker to take control of the affected system. An attacker could then 
  install programs; view, change, or delete data; or create new accounts with 
  full user rights and obtain sensitive information. 

  Impact Level: System");

  script_tag(name:"affected", value:"Microsoft Windows Server 2008 x32/x64 
  Edition Service Pack 2");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,
  https://support.microsoft.com/en-us/help/4024402");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/help/4024402");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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
fileVer = "";
maxVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(win2008:3, win2008x64:3) <= 0){
  exit(0);
}

## Get host
host = get_host_ip();

##Get Login Username
usrname = get_kb_item("SMB/login");

##Get Login Password
passwd  = get_kb_item("SMB/password");

##exit if Username or Password or host not available
if(!host || !usrname || !passwd){
  exit(0);
}

## Get the handle to execute wmi query
handle = wmi_connect(host:host, username:usrname, password:passwd);
if(!handle){
  exit(0);
}

## WMI query to grep the file version of 'httpext.dll'
query = 'Select Version from CIM_DataFile Where FileName ='
        + raw_string(0x22) +'tquery' +raw_string(0x22) + ' AND Extension ='
        + raw_string(0x22) +'dll' + raw_string(0x22);

## Get list of matched files
fileVer = wmi_query(wmi_handle:handle, query:query);
if(!fileVer){
  exit(0);
}

##Multiple files found
##On update old as well as new files come, so checking for highest version
foreach ver (split(fileVer))
{
  ver1 = eregmatch(pattern:"(.*)(windowssearchengine.*)\tquery.dll.?([0-9.]+)", string:ver);
  version = ver1[3];
  winPath = ver1[1] + ver1[2];;

  if(version_is_less(version:version, test_version:maxVer)){
    continue;
  } else {
    maxVer = version;
  }
}

if(maxVer)
{
 
  if(version_is_less(version:maxVer, test_version:"7.0.6002.19806")){
    Vulnerable_range = "Less than 7.0.6002.19806";
  }
  else if(version_in_range(version:maxVer, test_version:"7.0.6002.23000", test_version2:"7.0.6002.24125")){
    Vulnerable_range = "7.0.6002.23000 - 7.0.6002.24125";
  }
  if(Vulnerable_range)
  {
    report = 'File checked:     ' + winPath + "tquery.dll" + '\n' +
             'File version:     ' + maxVer  + '\n' +
             'Vulnerable range: ' + Vulnerable_range + '\n' ;
    security_message(data:report);
    exit(0);
  }
}

exit(0);
