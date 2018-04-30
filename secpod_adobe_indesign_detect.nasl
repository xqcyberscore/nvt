###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_indesign_detect.nasl 9644 2018-04-27 07:49:53Z santu $
#
# Adobe InDesign Version Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902084");
  script_version("$Revision: 9644 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-27 09:49:53 +0200 (Fri, 27 Apr 2018) $");
  script_tag(name:"creation_date", value:"2010-06-25 16:56:31 +0200 (Fri, 25 Jun 2010)");
  script_name("Adobe InDesign Version Detection");
  script_tag(name: "summary" , value: "Detection of installed version of
  Adobe InDesign.

  The script logs in via smb, searches for Adobe InDesign in the registry
  and gets the version from 'DisplayVersion' string from registry.");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Service detection");
  script_dependencies("secpod_reg_enum.nasl", "smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

## Variable Initialization
adName="";
adPath="";
adVer="";
osArch = "";
key = "";

## Get OS Architecture
os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(-1);
}

## Cofirm application installed or not
if(!registry_key_exists(key:"SOFTWARE\Adobe\InDesign") &&
   !registry_key_exists(key:"SOFTWARE\Wow6432Node\Adobe\InDesign")){
  exit(0);
}

## if os is 32 bit iterate over comman path
if("x86" >< os_arch){
  key_list =  make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

## Check for 64 bit platform
else if("x64" >< os_arch)
{
 key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                      "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    adName = registry_get_sz(key:key + item, item:"DisplayName");
    if("Adobe InDesign" >< adName)
    {
      ## Get the installed location from registry
      adPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!adPath){
        adPath = "Couldn find the install location from registry";
      }

      ## Get Adobe InDesign version from registry
      adVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      if(adVer != NULL)
      {
        tmp_version = adName + " " + adVer;
        set_kb_item(name:"Adobe/InDesign/Ver", value:tmp_version);
        log_message(data:adName + " version " + adVer + " installed at location " +
                       adPath + " was detected on the host");
      
        ## build cpe and store it as host_detail
        cpe = build_cpe(value:adVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:indesign_server:");
        if(!cpe)
          cpe = "cpe:/a:adobe:indesign_server"; 
        if("x64" >< osArch && "Wow6432Node" >!< key)
        {
          
          set_kb_item(name:"Adobe/InDesign/Ver64/Win/Ver", value:adVer);

          ## build cpe
          cpe = build_cpe(value:adVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:indesign_server:x64:");
          if(!cpe)
            cpe = "cpe:/a:adobe:indesign_server:x64";
        }
      
        register_product(cpe:cpe, location:adPath);
        log_message(data: build_detection_report(app: "Adobe Indesign",
                                                 version: adVer,
                                                 install: adPath,
                                                 cpe: cpe,
                                                 concluded: adVer));

      }
    }
  }
}
