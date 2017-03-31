###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_creative_cloud_detect_win.nasl 3153 2016-04-22 12:52:52Z antu123 $
#
# Adobe Creative Cloud Version Detection (Windows)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.807666");
  script_version("$Revision: 3153 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-04-22 14:52:52 +0200 (Fri, 22 Apr 2016) $");
  script_tag(name:"creation_date", value:"2016-04-14 18:14:10 +0530 (Thu, 14 Apr 2016)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Creative Cloud Version Detection (Windows)");

  script_tag(name : "summary" , value : "Detection of installed version
  of Adobe Digital Edition on Windows. 

  The script logs in via smb, searches for Adobe Digital in the registry
  and gets the version from registry.");

  script_summary("Detection of installed version of Adobe Creative Cloud on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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
cclName="";
cclPath="";
cclVer="";
osArch = "";
key_list = "";

## Get os architecture
osArch = get_kb_item("SMB/Windows/Arch");
if(!osArch){
  exit(-1);
}

## if os is 32 bit iterate over common path
if("x86" >< osArch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

#currently 64 bit app is not available
else if("x64" >< osArch){
  key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

foreach item (registry_enum_keys(key:key))
{
  cclName = registry_get_sz(key:key + item, item:"DisplayName");

  ## confirm the application
  if("Adobe Creative Cloud" >< cclName)
  {

    ## Get the version
    cclVer = registry_get_sz(key:key + item, item:"DisplayVersion");

    ## Get the installed path
    cclPath = registry_get_sz(key:key + item, item:"UninstallString");
    if(!cclPath){
      cclPath = "Couldn find the install location from registry";
    }

    if(cclVer)
    {
      set_kb_item(name:"AdobeCreativeCloud/Win/Ver", value:cclVer);

      ## build cpe
      cpe = build_cpe(value:cclVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:creative_cloud:");
      if(!cpe)
        cpe = "cpe:/a:adobe:creative_cloud";

      register_product(cpe:cpe, location:cclPath);
      log_message(data: build_detection_report(app: "Adobe Creative Cloud",
                                               version: cclVer,
                                               install: cclPath,
                                               cpe: cpe,
                                               concluded: cclVer));
      exit(0);
    }
  }
}
