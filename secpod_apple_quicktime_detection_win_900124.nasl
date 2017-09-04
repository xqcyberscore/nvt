##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apple_quicktime_detection_win_900124.nasl 7000 2017-08-24 11:51:46Z teissa $
#
# Apple QuickTime Version Detection for Windows
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Updated By: Antu Sanadi <santu@secpod.com> on 2013-07-07
# Updated according to new detection method.
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2014-09-02
# Updated to support 32 and 64 bit.
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900124");
  script_version("$Revision: 7000 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-08-24 13:51:46 +0200 (Thu, 24 Aug 2017) $");
  script_tag(name:"creation_date", value:"2008-09-25 09:10:39 +0200 (Thu, 25 Sep 2008)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Apple QuickTime Version Detection for Windows");

  tag_summary =
"Detection of installed version of Apple QuickTime.

The script logs in via smb, searches for executable of Apple QuickTime
'QuickTimePlayer.exe' and gets the file version.";


  script_tag(name : "summary" , value : tag_summary);

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2008 SecPod");
  script_dependencies("secpod_reg_enum.nasl", "smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}


include("cpe.inc");
include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variable Initialization
cpe = "";
quickTimePath = "";
quickTimeVer = "";

## Get OS Architecture
os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch)
{
  exit(-1);
}

## Check for 32 bit platform
if("x86" >< os_arch){
  key = "SOFTWARE\Apple Computer, Inc.\QuickTime";
}

## 64 bit app is not available
## so checking for 32 bit app on 64 bit.
else if("x64" >< os_arch){
  key = "SOFTWARE\Wow6432Node\Apple Computer, Inc.\QuickTime";
}

if(!registry_key_exists(key:key)){
  exit(0);
}

## Confirm the application installation and get the install path
quickTimePath = registry_get_sz(item:"InstallDir", key:key);
if(!quickTimePath){
  exit(0);
}

## Get the file vesion
quickTimeVer = fetch_file_version(sysPath:quickTimePath,
                                  file_name: "\QuickTimePlayer.exe");
if(quickTimeVer)
{
  ## Set the file version
  set_kb_item(name:"QuickTime/Win/Ver", value:quickTimeVer);

  ## Build CPE
  cpe = build_cpe(value:quickTimeVer, exp:"^([0-9.]+)", base:"cpe:/a:apple:quicktime:");
  if(isnull(cpe))
    cpe = "cpe:/a:apple:quicktime";

  ## Register the product
  register_product(cpe:cpe, location:quickTimePath);
  log_message(data: build_detection_report(app:"Apple QuickTime",
                                           version:quickTimeVer,
                                           install:quickTimePath,
                                           cpe:cpe,
                                           concluded:quickTimeVer));
}
