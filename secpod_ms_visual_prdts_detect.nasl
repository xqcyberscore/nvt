###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_visual_prdts_detect.nasl 5499 2017-03-06 13:06:09Z teissa $
#
# Microsoft Visual Product(s) Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900808");
  script_version("$Revision: 5499 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-03-06 14:06:09 +0100 (Mon, 06 Mar 2017) $");
  script_tag(name:"creation_date", value:"2009-08-03 06:30:10 +0200 (Mon, 03 Aug 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Microsoft Visual Products Version Detection");

  tag_summary =
"Detection of installed version of Microsoft Visual Products.

This script finds the installed product version of Microsoft Visual
Product(s) and sets the result in KB.";


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
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

## Variable Initialization
visual_key = "";
visualName = "";
studioVer = "";
insPath = "";
netVer = "";

NET_LIST = make_list("^(7\..*)", "cpe:/a:microsoft:visual_studio_.net:2003:",
                     "^(8\..*)", "cpe:/a:microsoft:visual_studio_.net:2005:",
                     "^(9\..*)", "cpe:/a:microsoft:visual_studio_.net:2008:");
NET_MAX = max_index(NET_LIST);

STUDIO_LIST = make_list("^(7\..*)", "cpe:/a:microsoft:visual_studio:2003:",
                        "^(8\..*)", "cpe:/a:microsoft:visual_studio:2005:",
                        "^(9\..*)", "cpe:/a:microsoft:visual_studio:2008:",
                        "^(10\..*)", "cpe:/a:microsoft:visual_studio:2010:");
STUDIO_MAX = max_index(STUDIO_LIST);

## functions for script
function register_cpe(tmpVers, tmpExpr, tmpBase, appName, appPath)
{
  local_var cpe;

  ## build cpe and store it as host_detail
  cpe = build_cpe(value:tmpVers, exp:tmpExpr, base:tmpBase);
  if(!isnull(cpe))
  {
    register_product(cpe:cpe, location:loc);

    log_message(data: build_detection_report(app: appName,
                                             version: tmpVers,
                                             install: appPath,
                                             cpe: cpe,
                                             concluded: tmpVers));
  }
}

# Check for Product Existence
if(!registry_key_exists(key:"SOFTWARE\Microsoft\VisualStudio"))
{
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\Microsoft\VisualStudio")){
    exit(0);
  }
}

## Get OS Architecture
os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch)
{
  exit(-1);
}

## Check for 32 bit platform
if("x86" >< os_arch){
  visual_key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

## Presently 64bit application is not available
## Check for 32 bit App on 64 bit platform
else if("x64" >< os_arch){
  visual_key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

foreach item (registry_enum_keys(key:visual_key))
{
  visualName = registry_get_sz(key:visual_key + item, item:"DisplayName");

  # Set the KB item for Microsoft Visual Studio
  if(visualName =~ "Microsoft Visual Studio [0-9]+")
  {
    studioVer = registry_get_sz(key:visual_key + item, item:"DisplayVersion");

    if(studioVer != NULL)
    {
      set_kb_item(name:"Microsoft/VisualStudio/Ver", value:studioVer);

      insPath = registry_get_sz(key:visual_key + item, item:"InstallLocation");
      if(!insPath){
        insPath = "Could not find the install Location from registry";
      }

      ## build cpe and store it as host_detail
      for (i = 0; i < STUDIO_MAX-1; i = i + 2)
      {
        register_cpe(tmpVers:studioVer, tmpExpr:STUDIO_LIST[i], tmpBase:STUDIO_LIST[i+1],
                           appName:visualName, appPath:insPath);
      }
    }
  }

  # Set the KB item for Microsoft Visual Studio .Net
  if(visualName =~ "Visual Studio \.NET [A-Za-z0-9]+")
  {
    netVer = registry_get_sz(key:visual_key + item, item:"DisplayVersion");
    if(netVer != NULL)
    {
      set_kb_item(name:"Microsoft/VisualStudio.Net/Ver", value:netVer);

      insPath = registry_get_sz(key:visual_key + item, item:"InstallLocation");
      if(!insPath){
        insPath = "Could not find the install Location from registry";
      }

      ## build cpe and store it as host_detail
      for (i = 0; i < NET_MAX-1; i = i + 2)
      {
        cpe = register_cpe(tmpVers:netVer, tmpExpr:NET_LIST[i], tmpBase:NET_LIST[i+1],
                           appName:visualName, appPath:insPath);
      }
    }
  }
}
