###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_winscp_detect_win.nasl 7000 2017-08-24 11:51:46Z teissa $
#
# WinSCP Version Detection (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803872");
  script_version("$Revision: 7000 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-08-24 13:51:46 +0200 (Thu, 24 Aug 2017) $");
  script_tag(name:"creation_date", value:"2013-08-21 12:41:35 +0530 (Wed, 21 Aug 2013)");
  script_tag(name:"qod_type", value:"registry");
  script_name("WinSCP Version Detection (Windows)");

  tag_summary =
"Detection of installed version of WinSCP.

The script logs in via smb, searches for WinSCP in the registry, gets
version from the 'DisplayVersion' string and set it in the KB item.";


  script_tag(name : "summary" , value : tag_summary);

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
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
appName = "";
insloc = "";
scpVer = "";

## Get OS Architecture
os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch)
{
  exit(-1);
}

## Check for 32 bit platform
if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

## Presently 64bit application is not available
## Check for 32 bit App on 64 bit platform
else if("x64" >< os_arch){
  key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  appName = registry_get_sz(key:key + item, item:"DisplayName");
  if(appName =~ "^WinSCP")
  {
    ## Get the Installed Path
    insloc = registry_get_sz(key:key + item, item:"InstallLocation");
    if(!insloc){
      insloc = "Could not find the install location from registry";
    }

    ## Get WinSCP Version
    scpVer = registry_get_sz(key:key + item, item:"DisplayVersion");

    if(scpVer != NULL)
    {
      set_kb_item(name:"WinSCP/Win/Ver", value:scpVer);

      ## build cpe and store it as host_detail
      cpe = build_cpe(value:scpVer, exp:"^([0-9.]+)", base:"cpe:/a:winscp:winscp:");
      if(isnull(cpe))
        cpe = "cpe:/a:winscp:winscp";

      register_product(cpe:cpe, location:insloc);

      log_message(data: build_detection_report(app: appName,
                                               version: scpVer,
                                               install: insloc,
                                               cpe: cpe,
                                               concluded: scpVer));
    }
  }
}
