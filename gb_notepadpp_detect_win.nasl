###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_notepadpp_detect_win.nasl 7022 2017-08-30 08:57:06Z santu $
#
# Notepad++ Version Detection (Windows)
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
# 
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805317");
  script_version("$Revision: 7022 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-08-30 10:57:06 +0200 (Wed, 30 Aug 2017) $");
  script_tag(name:"creation_date", value:"2015-01-09 13:19:25 +0530 (Fri, 09 Jan 2015)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Notepad++ Version Detection (Windows)");

  script_tag(name: "summary" , value:"Detection of installed version of
  Notepad++ on Windows.

  This script logs in via smb, searches for 'Notepad++' in the registry and
  gets the version from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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


## Variable Initialization
os_arch = "";
key = "";
noteVer = "";
notePath = "";

## Get OS Architecture
os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(-1);
}

## Check for 32 bit platform
if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Notepad++");
}

## Check for 64 bit platform, Currently only 32-bit application is available
else if("x64" >< os_arch){
  key_list =  make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Notepad++",
                        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Notepad++");
}

if(isnull(key_list)){
  exit(0);
}

foreach key (key_list)
{
  ##Grep Application Name
  noteName = registry_get_sz(key:key, item:"DisplayName");

  if("Notepad++" >< noteName)
  {
    ## Get Version from Registry
    noteVer = registry_get_sz(key:key, item:"DisplayVersion");
    if(!noteVer){
      exit(0);
    }

    ##Try to get Path from registry
    notePath = registry_get_sz(item:"UninstallString", key:key);
    if(!notePath){
      notePath = "Could not find the install location from registry";
    } 
    else{
      notePath = notePath - "\uninstall.exe";
    }

    set_kb_item(name:"Notepad++/Win/Ver", value:noteVer);

    ## build cpe
    cpe = build_cpe(value:noteVer, exp:"([0-9.]+)", base:"cpe:/a:don_ho:notepad++:");
    if(isnull(cpe))
      cpe = "cpe:/a:don_ho:notepad++";

    ## 64 bit apps on 64 bit platform
    if("x64" >< os_arch && "Wow6432Node" >!< key)
    {
      set_kb_item(name:"Notepad++64/Win/Ver", value:noteVer);

      ## build cpe and store it as host_detail
      cpe = build_cpe(value:noteVer, exp:"^([0-9.]+)", base:"cpe:/a:don_ho:notepad++:x64:");
      if(isnull(cpe))
        cpe = "cpe:/a:don_ho:notepad++:x64";
    }

    ## Register Product and Build Report
    register_product(cpe:cpe, location:notePath);

    log_message(data: build_detection_report(app: "Notepad++",
                                             version: noteVer,
                                             install: notePath,
                                             cpe: cpe,
                                             concluded: noteVer));
    exit(0);
  }
}
