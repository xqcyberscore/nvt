####################################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ccleaner_detect_win.nasl 10039 2018-05-31 12:28:58Z mmartin $
#
# CCleaner Detection (Windows)
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
####################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811777");
  script_version("$Revision: 10039 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-05-31 14:28:58 +0200 (Thu, 31 May 2018) $");
  script_tag(name:"creation_date", value:"2017-09-19 11:52:53 +0530 (Tue, 19 Sep 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("CCleaner Detection (Windows)");

  script_tag(name: "summary" , value: "Detection of installed version of
  CCleaner (Free and Professional Editions).

  The script logs in via smb, searches for 'CCleaner' string, gets the installation
  path from 'InstallLocation' string from registry and fetches version from
  executable 'CCleaner.exe'.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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
appName = "";
appVer = "";
key = "";
insloc = "";
checkduplicate = ""; # Keep in here to make openvas-nasl-lint happy...
## Get OS Architecture
os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

## Application confirmation
## Key is same for x86 and x64 Platforms
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CCleaner";
if(!registry_key_exists(key:key)){
  exit(0);
}

##Get AppName
appName = registry_get_sz(key:key, item:"DisplayName");
##Confirm Application
if("CCleaner" >< appName)
{
  ## Get the Installed Path
  insloc = registry_get_sz(key:key + item, item:"InstallLocation");
  if(!insloc){
    exit(0);
  }
  location = insloc;
  ##Get Version
  appVer = fetch_file_version(sysPath:insloc, file_name:"CCleaner.exe");  
  if(appVer)
  {
    ## Set KB
    set_kb_item(name:"CCleaner/Win/Ver", value:appVer);

    ## build cpe
    cpe = build_cpe(value:appVer, exp:"([0-9.]+)", base:"cpe:/a:piriform:ccleaner:");
    if(isnull(cpe)){
        cpe = "cpe:/a:piriform:ccleaner";
    }

    ## 64 bit app on 64 bit platform
    if("x64" >< os_arch)
    {
      set_kb_item(name:"CCleanerx64/Win/Ver", value:appVer);

 # TODO: Fix the detection instead of ignoring e.g. the same
 # version of 32bit and 64bit apps are installed...
 ##If same Thunderbird version has been detected already continue
    if(appVer + ", " >< checkduplicate){
      continue;
    }
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:appVer, exp:"^([0-9.]+)", base:"cpe:/a:piriform:ccleaner:x64:");
      if(isnull(cpe))
        cpe = "cpe:/a:piriform:ccleaner:x64";
    }

    if(location){
    ##Assign detected version value to checkduplicate so as to check in next loop iteration
      checkduplicate += appVer + ", ";
    # Used in gb_ccleaner_detect_portable_win.nasl to detect doubled detections
      set_kb_item(name:"CCleaner/Win/InstallLocations", value:tolower(location));
      register_product(cpe:cpe, location:location);
      log_message(port:0, data:build_detection_report(app:appName, version:appVer, install:location, cpe:cpe, concluded:appVer));
  
    exit(0);
    }
  }
}
exit(0);
