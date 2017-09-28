###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_xnview_detect_win.nasl 7293 2017-09-27 08:49:48Z cfischer $
#
# XnView Version Detection
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Updated By: Shakeel <bshakeel@secpod.com> on 2014-09-02
# To support 32 and 64 bit.
#
# Copyright:
# Copyright (C) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900751");
  script_version("$Revision: 7293 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-09-27 10:49:48 +0200 (Wed, 27 Sep 2017) $");
  script_tag(name:"creation_date", value:"2010-03-30 16:15:33 +0200 (Tue, 30 Mar 2010)");
  script_tag(name:"qod_type", value:"registry");
  script_name("XnView Version Detection");

  tag_summary =
"Detection of installed version of XnView.

The script logs in via smb, searches for XnView in the registry and
gets the version from 'DisplayVersion' string in registry";


  script_tag(name : "summary" , value : tag_summary);

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
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
os_arch = "";
key = "";
xnviewVer= "";
insloc= "";

## Get OS Architecture
os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(-1);
}

## Check for 32 bit platform
if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\XnView_is1";
}

## Check for 64 bit platform, Currently only 32-bit application is available
else if("x64" >< os_arch){
  key =  "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\XnView_is1";
}

if(isnull(key)){
  exit(0);
}

## Confirm Application
if(!registry_key_exists(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\XnView_is1"))
{
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\XnView_is1")){
    exit(0);
  }
}

## Get XnView Version
xnviewVer = registry_get_sz(key:key, item:"DisplayVersion");
if(!xnviewVer){
  exit(0);
}

insloc = registry_get_sz(key:key, item:"InstallLocation");
if(!insloc){
  insloc = "Could not find the install location from registry";
}

set_kb_item(name:"XnView/Win/Ver", value:xnviewVer);

## build cpe and store it as host_detail
cpe = build_cpe(value:xnviewVer, exp:"^([0-9.]+)", base:"cpe:/a:xnview:xnview:");
if(isnull(cpe))
  cpe = "cpe:/a:xnview:xnview";

register_product(cpe:cpe, location:insloc);

log_message(data: build_detection_report(app:"XnView ",
                                         version:xnviewVer,
                                         install:insloc,
                                         cpe:cpe,
                                         concluded:xnviewVer));
