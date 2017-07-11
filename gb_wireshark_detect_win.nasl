###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_detect_win.nasl 6235 2017-05-29 13:45:48Z cfi $
#
# Wireshark Version Detection (Windows)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Update By:  Thanga Prakash S <tprakash@secpod.com> on 2013-09-27
# According to cr57 and new style script_tags.
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2014-08-28
# Updated to support 32 and 64 bit.
#
# Updated By: Kashinath T <tkashinath@secpod.com> on 2016-04-05
# Updated to build proper reports
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800038");
  script_version("$Revision: 6235 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-05-29 15:45:48 +0200 (Mon, 29 May 2017) $");
  script_tag(name:"creation_date", value:"2008-10-24 15:11:55 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Wireshark Version Detection (Windows)");

  tag_summary =
"Detection of installed version of Wireshark on Windows.

The script logs in via smb, searches for Wireshark in the registry
and gets the version from registry.";


  script_tag(name : "summary" , value : tag_summary);

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl", "smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

## Variable Initialization
wiresharkVer = "";
wireName = "";
path = "";
cpe = "";

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

## For 64 bit app also key is creating under Wow6432Node
else if("x64" >< os_arch){
  key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

if(!registry_key_exists(key:key)){
  exit(0);
}

wireName = registry_get_sz(key: key + "Wireshark", item:"DisplayName");

## Confirm Wireshark
if("Wireshark" >< wireName)
{
  ## Get the Version
  wiresharkVer = registry_get_sz(key: key + "Wireshark", item:"DisplayVersion");

  path = registry_get_sz(key: key + "Wireshark", item:"UninstallString");
  if(path){
    path = path - "\uninstall.exe";
  } else {
    path = "Unable to find the install location from registry.";
  }

  if(wiresharkVer)
  {
    set_kb_item(name:"Wireshark/Win/Ver", value:wiresharkVer);

    ## Build cpe
    cpe = build_cpe(value:wiresharkVer, exp:"^([0-9.]+)", base:"cpe:/a:wireshark:wireshark:");
    if(isnull(cpe))
      cpe = 'cpe:/a:wireshark:wireshark';
 
    ## Register for 64 bit app on 64 bit OS once again
    if("64" >< os_arch && "64-bit" >< wireName)
    {
      set_kb_item(name:"Wireshark64/Win/Ver", value:wiresharkVer);

      ## Build cpe
      cpe = build_cpe(value:wiresharkVer, exp:"^([0-9.]+)", base:"cpe:/a:wireshark:wireshark:x64:");
      if(isnull(cpe))
        cpe = 'cpe:/a:wireshark:wireshark:x64';
    }

    register_product(cpe:cpe, location:path);

    log_message(data: build_detection_report(app: wireName,
                                             version: wiresharkVer,
                                             install: path,
                                             cpe: cpe,
                                             concluded: wiresharkVer));
  }
}
