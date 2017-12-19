###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_python_detect_win.nasl 8159 2017-12-18 15:10:39Z cfischer $
#
# Python Version Detection (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Update By:  Shakeel <bshakeel@secpod.com> on 2014-03-05
# According to cr57 and new style script_tags.
#
# Updated By: Shakeel <bshakeel@secpod.com> on 2014-06-24
# According to CR57 and to support 32 and 64 bit.
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801795");
  script_version("$Revision: 8159 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-12-18 16:10:39 +0100 (Mon, 18 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-06-07 13:29:28 +0200 (Tue, 07 Jun 2011)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Python Version Detection (Windows)");

  tag_summary =
  "This script detects the installed version of Python on Windows.

The script logs in via smb, searches for Python in the registry and gets the
Python path and version from registry.";


  script_tag(name : "summary" , value : tag_summary);

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
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
os_arch = "";
key_list = "";
key="";
pyPath="";
pyVer="";

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
else if("x64" >< os_arch){
  key_list =  make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if(isnull(key_list)){
  exit(0);
}


## Confirm Application
if(!registry_key_exists(key:"SOFTWARE\Python")){
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\Python")){
    exit(0);
  }
}

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    pyName = registry_get_sz(key:key + item, item:"DisplayName");

    ## Confirm for Python
    if("Python" >< pyName)
    {
      ##Get Python install Path
      pyPath = registry_get_sz(key:key + item, item:"DisplayIcon");
      if(!pyPath)
        pyPath = "Could not find the install location from registry";
      else
        pyPath = pyPath - "python.exe";

      ##Get Python Version
      pyVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      if(pyVer) {
        set_kb_item(name:"Python6432/Win/Installed", value:TRUE);
        if("x64" >< os_arch && "Wow6432Node" >!< key) {
          set_kb_item(name:"Python64/Win/Ver", value:pyVer);
          register_and_report_cpe( app:"Python", ver:pyVer, base:"cpe:/a:python:python:x64:", expr:"^([0-9.]+)", insloc:pyPath );
        } else {
          set_kb_item(name:"Python/Win/Ver", value:pyVer);
          register_and_report_cpe( app:"Python", ver:pyVer, base:"cpe:/a:python:python:", expr:"^([0-9.]+)", insloc:pyPath );
        }
      }
    }
  }
}
