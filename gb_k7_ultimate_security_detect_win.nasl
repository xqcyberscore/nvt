###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_k7_ultimate_security_detect_win.nasl 8199 2017-12-20 13:37:22Z cfischer $
#
# K7 Ultimate Security Version Detection (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.805462");
  script_version("$Revision: 8199 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-12-20 14:37:22 +0100 (Wed, 20 Dec 2017) $");
  script_tag(name:"creation_date", value:"2015-01-02 11:26:06 +0530 (Fri, 02 Jan 2015)");
  script_name("K7 Ultimate Security Version Detection (Windows)");

  script_tag(name: "summary" , value: "Detection of installed version of
  K7 Ultimate Security.

  The script logs in via smb, searches for K7 Ultimate Security in the registry
  and gets the version from 'DisplayVersion' string from registry.");

  script_tag(name:"qod_type", value:"registry");
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
k7usecPath = "";
k7usecVer = "";
k7usecName = "";

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

if(isnull(key_list)){
  exit(0);
}

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    k7usecName = registry_get_sz(key:key + item, item:"DisplayName");

    ## Confirm for K7UltimateSecurity
    if("K7UltimateSecurity" >< k7usecName)
    {
      k7usecVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      k7usecPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!k7usecPath) {
        k7usecPath = "Unable to find the install location from registry";
      }

      set_kb_item(name:"K7/UltimateSecurity/Win/Installed", value:TRUE);

      ## Register for 64 bit app on 64 bit OS
      if("64" >< os_arch && "Wow6432Node" >!< key) {
        set_kb_item(name:"K7/UltimateSecurity64/Win/Ver", value:k7usecVer);
        register_and_report_cpe( app:"K7 UltimateSecurity", ver:k7usecVer, base:"cpe:/a:k7computing:ultimate_security:x64:", expr:"^([0-9.]+)", insloc:k7usecPath );
      } else {
        set_kb_item(name:"K7/UltimateSecurity/Win/Ver", value:k7usecVer);
        register_and_report_cpe( app:"K7 UltimateSecurity", ver:k7usecVer, base:"cpe:/a:k7computing:ultimate_security:", expr:"^([0-9.]+)", insloc:k7usecPath );
      }
    }
  }
}
