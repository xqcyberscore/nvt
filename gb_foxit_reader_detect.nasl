###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foxit_reader_detect.nasl 8140 2017-12-15 12:08:32Z cfischer $
#
# Foxit Reader Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Updated By: Shakeel <bshakeel@secpod.com> on 2014-06-03
# According to CR57 and to support 32 and 64 bit.
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800536");
  script_version("$Revision: 8140 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-12-15 13:08:32 +0100 (Fri, 15 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-03-17 05:28:51 +0100 (Tue, 17 Mar 2009)");
  script_name("Foxit Reader Version Detection");

  script_tag(name: "summary" , value: "Detection of installed version of
  Foxit Reader.

  The script logs in via smb, searches for Foxit Reader in the registry
  and gets the version from registry.");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl", "smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");
include("version_func.inc");

## variable Initialization
os_arch = "";
key_list = "";
key = "";
cpe = "";
foxitVer = "";
foxitPath = "";

## Get OS Architecture
os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(-1);
}

## Check for 32 bit platform
if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Foxit Software\Foxit Reader");
}

## Check for 64 bit platform, Currently only 32-bit application is available
else if("x64" >< os_arch)
{
  key_list =  make_list("SOFTWARE\Wow6432Node\Foxit Software\Foxit Reader");
}

if(isnull(key_list)){
    exit(0);
}

## Confirm Application
if(!registry_key_exists(key:"SOFTWARE\Foxit Software\Foxit Reader")){
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\Foxit Software\Foxit Reader")){
    exit(0);
  }
}

## Get Version from Registry
foreach key (key_list)
{
  foxitVer = registry_get_sz(key:key, item:"Version");
  foxitPath = registry_get_sz(key:key, item:"InstallPath");
  if(!foxitPath){
    foxitPath = registry_get_sz(key:key, item:"InstallLocation");
  }

  if(!foxitVer)
  {
    if(foxitPath){
      foxitVer = fetch_file_version(sysPath:foxitPath, file_name:"Foxit Reader.exe");
       if(!foxitVer){
         foxitVer = fetch_file_version(sysPath:foxitPath, file_name:"FoxitReader.exe");
       }
     }
    else
    {
      foxitPath = registry_get_sz(key:key, item:"InnoSetupUpdatePath");
      if(foxitPath)
      {
        foxitPath = foxitPath - "unins000.exe";
        foxitVer = fetch_file_version(sysPath:foxitPath, file_name:"Foxit Reader.exe");
      }
    }
  }

  if(foxitVer)
  {
    set_kb_item(name:"Foxit/Phantom_or_Reader/Installed", value:TRUE);
    set_kb_item(name:"Foxit/Reader/Ver", value:foxitVer);

    if(!foxitPath){
      foxitPath = 'Could not find the install path from registry';
    }
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:foxitVer, exp:"^([0-9.]+)", base:"cpe:/a:foxitsoftware:reader:");
    if(isnull(cpe))
      cpe = "cpe:/a:foxitsoftware:reader";

    register_product(cpe:cpe, location:foxitPath);

    log_message(data: build_detection_report(app:"Foxit Reader",
                                             version:foxitVer,
                                             install:foxitPath,
                                             cpe:cpe,
                                             concluded:foxitVer));
  }
}
