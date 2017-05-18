##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_tightvnc_detect_win.nasl 6032 2017-04-26 09:02:50Z teissa $
#
# TightVNC Version Detection (Windows)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900472");
  script_version("$Revision: 6032 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-04-26 11:02:50 +0200 (Wed, 26 Apr 2017) $");
  script_tag(name:"creation_date", value:"2009-03-03 06:56:37 +0100 (Tue, 03 Mar 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("TightVNC Version Detection (Windows)");

tag_summary =
"Detection of installed version of TightVNC.

The script logs in via smb, searches for TightVNC in the registry and
gets the version from registry.";


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

osArch = "";
key_list = "";
appName = "";
appLoc = "";
vncVer = "";

osArch = get_kb_item("SMB/Windows/Arch");
if(!osArch)
{
  exit(-1);
}

## if os is 32 bit iterate over common path
if("x86" >< osArch){
  key_list = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

## Check for 64 bit platform
else if("x64" >< osArch){
 key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                      "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    appName = registry_get_sz(key:key + item, item:"DisplayName");

    # Confirm the application
    if("TightVNC" >< appName)
    {
      vncVer = registry_get_sz(key:key + item, item:"DisplayVersion");

      if(vncVer)
      {
        appLoc = registry_get_sz(key:key + item, item:"InstallLocation");
        if(!appLoc){
          appLoc = "Couldn find the install location from registry";
        }

        # Set KB for TightVNC
        set_kb_item(name:"TightVNC/Win/Ver", value:vncVer);

        cpe = build_cpe(value:vncVer, exp:"^([0-9.]+)", base:"cpe:/a:tightvnc:tightvnc:");
        if(isnull(cpe))
          cpe = "cpe:/a:tightvnc:tightvnc";

        ## 64 bit apps on 64 bit platform
        if("x64" >< osArch && "Wow6432Node" >!< key)
        {
          set_kb_item(name:"TightVNC64/Win/Ver", value:vncVer);

          cpe = build_cpe(value:vncVer, exp:"^([0-9.]+)", base:"cpe:/a:tightvnc:tightvnc:x64:");
          if(isnull(cpe))
            cpe = "cpe:/a:tightvnc:tightvnc:x64";

        }
        ## Register Product and Build Report
        register_product(cpe:cpe, location:appLoc);
        log_message(data: build_detection_report(app: appName,
                                                 version: vncVer,
                                                 install: appLoc,
                                                 cpe: cpe,
                                                 concluded: vncVer));

      }
    }
  }
}
