###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_libre_office_detect_win.nasl 2672 2016-02-17 07:38:35Z antu123 $
#
# LibreOffice Version Detection (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Updated By Shakeel <bshakeel@secpod.com> on 2014-11-19
# According to new script style
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2014-07-08
# Updated to support 32 and 64 bit
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
  script_oid("1.3.6.1.4.1.25623.1.0.902398");
  script_version("$Revision: 2672 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-02-17 08:38:35 +0100 (Wed, 17 Feb 2016) $");
  script_tag(name:"creation_date", value:"2011-07-27 09:16:39 +0200 (Wed, 27 Jul 2011)");
  script_tag(name:"qod_type", value:"registry");
  script_name("LibreOffice Version Detection (Windows)");

  script_tag(name: "summary" , value: "Detection of installed version of
  LibreOffice on Windows.

  The script logs in via smb, searches for LibreOffice in the registry
  and gets the version from registry.");

  script_summary("Set KB for the version of LibreOffice");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
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
officeName = "";
officePath = "";
officeVer = "";

if(!registry_key_exists(key:"SOFTWARE\LibreOffice"))
{
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\LibreOffice")){
    exit(0);
  }
}

## Get OS Architecture
os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(-1);
}

## Check for 32 bit platform
if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

## Check for 32 bit App on 64 bit platform
else if("x64" >< os_arch){
  key_list =  make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if(isnull(key_list)){
  exit(0);
}

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    officeName = registry_get_sz(key:key + item, item:"DisplayName");

    ## Check the name of the application
    if("LibreOffice" >< officeName)
    {
      ## Check for the version
      officeVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      if (officeVer != NULL)
      {
        officePath = registry_get_sz(key:key + item, item:"InstallLocation");
        if(!officePath){
          officePath = "Could not able to get the install location";
        }

        ## Set the KB item
        set_kb_item(name:"LibreOffice/Win/Ver", value:officeVer);

        ## build cpe and store it as host_detail
        cpe = build_cpe(value:officeVer, exp:"^([0-9.]+)", base:"cpe:/a:libreoffice:libreoffice:");
        if(isnull(cpe))
          cpe = "cpe:/a:libreoffice:libreoffice";

        if("64" >< os_arch && "Wow6432Node" >!< key)
        {
          set_kb_item(name:"LibreOffice64/Win/Ver", value:officeVer);
          cpe = build_cpe(value:officeVer, exp:"^([0-9.]+)", base:"cpe:/a:libreoffice:libreoffice:x64:");

          if(isnull(cpe))
            cpe = "cpe:/a:libreoffice:libreoffice:x64";
        }
        register_product(cpe:cpe, location:officePath);
        log_message(data: build_detection_report(app: officeName, version: officeVer,
                                                 install: officePath, cpe:cpe, concluded:officeVer));
      }
    }
  }
}
