###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_indusoft_web_studio_detect_win.nasl 8158 2017-12-18 13:18:20Z cfischer $
#
# InduSoft Web Studio Version Detection (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806001");
  script_version("$Revision: 8158 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-12-18 14:18:20 +0100 (Mon, 18 Dec 2017) $");
  script_tag(name:"creation_date", value:"2015-08-19 15:48:22 +0530 (Wed, 19 Aug 2015)");
   script_tag(name:"qod_type", value:"registry");
  script_name("InduSoft Web Studio Version Detection (Windows)");

  script_tag(name: "summary" , value: "Detection of installed version of
  InduSoft Web Studio.

  The script logs in via smb, searches for InduSoft Web Studio in the registry
  and gets the version from 'DisplayVersion' string from registry.");
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

## variable Initialization
os_arch = "";
key_list = "";
key = "";
studioPath = "";
studioVer = "";
studioName = "";

## Get OS Architecture
os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

## Check for 32 bit platform
if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

## Check for 64 bit platform
## 64 bit App is not available
else if("x64" >< os_arch)
{
  key_list =  make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if(isnull(key_list)){
  exit(0);
}

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    studioName = registry_get_sz(key:key + item, item:"DisplayName");

    ## Confirm application 
    if("InduSoft Web Studio" >< studioName)
    {
      studioVer = registry_get_sz(key:key + item, item:"DisplayVersion");

      studioPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!studioPath){
        studioPath = "Unable to find the install location from registry";
      }

      if(studioVer)
      {
        set_kb_item(name:"InduSoft/WebStudio/Win/Ver", value:studioVer);
        register_and_report_cpe( app:"InduSoft Web Studio", ver:studioVer, base:"cpe:/a:schneider_electric:indusoft_web_studio:", expr:"^([0-9.]+)", insloc:studioPath );
      }
    }
  }
}
