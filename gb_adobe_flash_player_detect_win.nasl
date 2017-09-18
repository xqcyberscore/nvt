###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_detect_win.nasl 7153 2017-09-15 15:03:32Z cfischer $
#
# Adobe Flash Player/Flash CS/AIR/Flex Version Detection (Windows)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2013-09-18
# According to CR57 and new style script_tags.
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
  script_oid("1.3.6.1.4.1.25623.1.0.800029");
  script_version("$Revision: 7153 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-09-15 17:03:32 +0200 (Fri, 15 Sep 2017) $");
  script_tag(name:"creation_date", value:"2008-10-16 18:25:33 +0200 (Thu, 16 Oct 2008)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Flash Player/Flash CS/AIR/Flex Version Detection (Windows)");

  tag_summary =
"Detection of installed version of Adobe Flash Player/Flash CS/AIR/Flex
on Windows.

The script logs in via smb, searches for Adobe Products in the registry
and gets the version from 'DisplayVersion' string in registry.";


  script_tag(name : "summary" , value : tag_summary);

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl", "smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  exit(0);
}


include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");

## variable Initialization
adobeName = "";
playerFlag = 0;
flexFlag = 0;
airFlag = 0;
csFlag = 0;
os_arch = "";
checkduplicate = "";
checkduplicate_path = "";

## Get OS Architecture
os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(-1);
}

## Check for 32 bit platform
if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

## Check for 64 bit platform
else if("x64" >< os_arch)
{
  key_list =  make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    adobeName = registry_get_sz(key:key + item, item:"DisplayName");

    ## Confirm for Adobe AIR
    if("Adobe AIR" >< adobeName && airFlag == 0)
    {
      airVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      insPath = registry_get_sz(key:key + item, item:"InstallLocation");

      if(airVer != NULL)
      {

        ## Check if version is already set
        if (airVer + ", " >< checkduplicate && insPath + ", " >< checkduplicate_path){
          continue;
        }
        ##Assign detectted version value to checkduplicate so as to check in next loop iteration
        checkduplicate  += airVer + ", ";
        checkduplicate_path += insPath + ", ";

        set_kb_item(name:"Adobe/Air/Win/Ver", value:airVer);
        replace_kb_item(name:"Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed", value:TRUE);

        ## Build CPE
        cpe = build_cpe(value:airVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:adobe_air:");
        if(isnull(cpe))
          cpe = "cpe:/a:adobe:adobe_air";

        ## Register for 64 bit app on 64 bit OS once again
        if("64" >< os_arch && "Wow6432Node" >!< key)
        {
          set_kb_item(name:"Adobe/Air64/Win/Ver", value:airVer);
          cpe = build_cpe(value:airVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:adobe_air:x64:");
          if(isnull(cpe))
            cpe = "cpe:/a:adobe:adobe_air:x64";
        }
 
        register_product(cpe:cpe, location:insPath);
        build_report(app: adobeName, ver: airVer, cpe: cpe, insloc: insPath);
      }
    }

    ## Confirm for Adobe Flash CS
    else if("Adobe Flash CS" >< adobeName && csFlag == 0)
    {
      fcsVer = eregmatch(pattern:"Flash (CS[0-9])", string:adobeName);
      insPath = registry_get_sz(key:key + item, item:"InstallLocation");

      if(fcsVer[1] != NULL)
      {
        set_kb_item(name:"Adobe/FlashCS/Win/Ver", value:fcsVer[1]);
        replace_kb_item(name:"Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed", value:TRUE);

        ## Build CPE
        cpe = build_cpe(value:fcsVer[1], exp:"^([0-9.]+)", base:"cpe:/a:adobe:flash_cs:");
        if(isnull(cpe))
          cpe = "cpe:/a:adobe:flash_cs";

        ## Register for 64 bit app on 64 bit OS once again
        if("64" >< os_arch && "Wow6432Node" >!< key)
        {
          set_kb_item(name:"Adobe/FlashCS64/Win/Ver", value:fcsVer[1]);
          cpe = build_cpe(value:fcsVer[1], exp:"^([0-9.]+)", base:"cpe:/a:adobe:flash_cs:x64:");
          if(isnull(cpe))
            cpe = "cpe:/a:adobe:flash_cs:x64";
        }
        
        register_product(cpe:cpe, location:insPath);
        ## Build Report
        build_report(app: adobeName, ver: fcsVer[1], cpe: cpe, insloc: insPath);
      }
    }

    ## Confirm for Adobe Flash Player
    else if("Adobe Flash Player" >< adobeName && playerFlag == 0)
    {
      playerVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      insPath = registry_get_sz(key:key + item, item:"InstallLocation");

      if(!insPath){
        insPath = registry_get_sz(key:key + item, item:"DisplayIcon");
      }

      if(!insPath){
        insPath = "Could not find the install location from registry";
      }

      if(playerVer != NULL)
      {
        set_kb_item(name:"AdobeFlashPlayer/Win/Ver", value:playerVer);
        replace_kb_item(name:"Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed", value:TRUE);

        ## Build CPE
        cpe = build_cpe(value:playerVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:flash_player:");
        if(isnull(cpe))
          cpe = "cpe:/a:adobe:flash_player";

        ## Register for 64 bit app on 64 bit OS once again
        if("64" >< os_arch && "Wow6432Node" >!< key)
        {
          set_kb_item(name:"AdobeFlashPlayer64/Win/Ver", value:playerVer);
          cpe = build_cpe(value:playerVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:flash_player:x64:");
          if(isnull(cpe))
            cpe = "cpe:/a:adobe:flash_player:x64";
        }
       
        register_product(cpe:cpe, location:insPath);
        ## Register Product and Build Report
        build_report(app: adobeName, ver: playerVer, cpe: cpe, insloc: insPath);

        ## Commented as we need to find multiple adobe versions for 
        ## IE and other browsers
        #playerFlag = 1;
      }
    }

    ## Confirm for Adobe Flex
    else if("Adobe Flex" >< adobeName && flexFlag == 0)
    {
      flexVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      insPath = registry_get_sz(key:key + item, item:"InstallLocation");

      if(flexVer != NULL)
      {
        set_kb_item(name:"Adobe/Flex/Win/Ver", value:flexVer);

        ## Build CPE
        cpe = build_cpe(value:flexVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:flex:");
        if(isnull(cpe))
          cpe = "cpe:/a:adobe:flex";

        ## Register for 64 bit app on 64 bit OS once again
        if("64" >< os_arch && "Wow6432Node" >!< key)
        {
          set_kb_item(name:"Adobe/Flex64/Win/Ver", value:flexVer);
          cpe = build_cpe(value:flexVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:flex:x64:");
          if(isnull(cpe))
            cpe = "cpe:/a:adobe:flex:x64";
        }

        register_product(cpe:cpe, location:insPath);
        ## Register Product and Build Report
        build_report(app: adobeName, ver:flexVer, cpe: cpe, insloc: insPath);
      }
    }
  }
}
