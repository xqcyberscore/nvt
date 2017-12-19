###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_security_scan_plus_detect.nasl 8159 2017-12-18 15:10:39Z cfischer $
#
# Intel Security McAfee Security Scan Plus Version Detection (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.810823");
  script_version("$Revision: 8159 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-12-18 16:10:39 +0100 (Mon, 18 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-03-22 11:19:49 +0530 (Wed, 22 Mar 2017)");
  script_name("Intel Security McAfee Security Scan Plus Version Detection (Windows)");

  script_tag(name: "summary" , value: "Detection of installed version of
  Intel Security McAfee Security Scan Plus.

  The script logs in via smb, searches for string 'McAfee Security Scan Plus'
  in the registry and reads the version information from registry.");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl", "smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

## variable Initialization
os_arch = "";
key_list = "";
prot_Path = "";
prot_Name = "";
prot_Ver = "";
cpe = "";
key = "";

## Get OS Architecture
os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(-1);
}

## Check for 32 bit platform
if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\McAfee Security Scan\";
}

## Check for 64 bit platform, only 32-bit app is available
else if("x64" >< os_arch){
  key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\McAfee Security Scan\";
}
 
if(isnull(key)){
  exit(0);
}

##Get Name
prot_Name = registry_get_sz(key:key + item, item:"HideDisplayName");

#### Confirm Application
if("McAfee Security Scan Plus" >< prot_Name)
{
  prot_Ver = registry_get_sz(key:key + item, item:"DisplayVersion");
  prot_Path = registry_get_sz(key:key + item, item:"InstallDirectory");

  if(!prot_Path){
    prot_Path = "Couldn find the install location from registry";
  }

  if(prot_Ver)
  {
    set_kb_item(name:"McAfee/SecurityScanPlus/Win/Ver", value:prot_Ver);
    register_and_report_cpe( app:"Intel Security McAfee Security Scan Plus", ver:prot_Ver, base:"cpe:/a:intel:mcafee_security_scan_plus:", expr:"^([0-9.]+)", insloc:prot_Path );
    exit(0); 
  }  
}
