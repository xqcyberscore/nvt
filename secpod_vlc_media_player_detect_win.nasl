###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_vlc_media_player_detect_win.nasl 8162 2017-12-19 06:15:07Z cfischer $
#
# VLC Media Player Version Detection (Windows)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Updated By: Shashi Kiran N <nskiran@secpod.com> on 2013-10-22
# According to new style script_tags.
#
# Updated By: Shakeel <bshakeel@secpod.com> on 2014-08-07
# To support 32 and 64 bit.
#
# Copyright:
# Copyright (C) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900528");
  script_version("$Revision: 8162 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-12-19 07:15:07 +0100 (Tue, 19 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-03-26 11:19:12 +0100 (Thu, 26 Mar 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("VLC Media Player Version Detection (Windows)");

  tag_summary =
"Detection of installed version of VLC Media Player version on Windows.

The script logs in via smb, searches for VLC Media Player in the registry
and gets the version from registry.";


  script_tag(name : "summary" , value : tag_summary);

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
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
key_list = "";
key = "";
vlcVer = "";
vlcPath = "";

## Get OS Architecture
os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(-1);
}

## Check for 32 bit platform
if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\VideoLAN\VLC");
}

## Check for 64 bit platform, Currently only 32-bit application is available
else if("x64" >< os_arch){
  key_list =  make_list("SOFTWARE\VideoLAN\VLC",
                        "SOFTWARE\Wow6432Node\VideoLAN\VLC");
}

if(isnull(key_list)){
  exit(0);
}

## Confirm Application
if(!registry_key_exists(key:"SOFTWARE\VideoLAN\VLC")) {
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\VideoLAN\VLC")){
    exit(0);
  }
}

foreach key (key_list)
{
  vlcVer = registry_get_sz(item:"Version", key:key);
  vlcPath = registry_get_sz(item:"InstallDir", key:key);

  if(vlcVer != NULL && vlcPath != NULL)
  {

    set_kb_item(name:"VLCPlayer/Win/Installed", value:TRUE);

    ## 64 bit apps on 64 bit platform
    if("x64" >< os_arch && "Wow6432Node" >!< key) {
      set_kb_item(name:"VLCPlayer64/Win/Ver", value:vlcVer);
      register_and_report_cpe( app:"VLC Media Player", ver:vlcVer, base:"cpe:/a:videolan:vlc_media_player:x64:", expr:"^([0-9.]+([a-z0-9]+)?)", insloc:vlcPath );
    } else {
      set_kb_item(name:"VLCPlayer/Win/Ver", value:vlcVer);
      register_and_report_cpe( app:"VLC Media Player", ver:vlcVer, base:"cpe:/a:videolan:vlc_media_player:", expr:"^([0-9.]+([a-z0-9]+)?)", insloc:vlcPath );
    }
  }
}
