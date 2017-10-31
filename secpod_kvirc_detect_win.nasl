##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_kvirc_detect_win.nasl 7582 2017-10-26 11:56:51Z cfischer $
#
# KVIrc Version Detection (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By: Shakeel <bshakeel@secpod.com> on 2014-05-20
# According to CR57 and to support 32 and 64 bit.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901010");
  script_version("$Revision: 7582 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 13:56:51 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2009-09-02 09:58:59 +0200 (Wed, 02 Sep 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("KVIrc Version Detection (Windows)");

  tag_summary =
"This script detects the installed version of KVIrc and sets the result in
KB.

The script logs in via smb, searches for KVIrc in the registry, and gets the
version from registry.";


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
include("version_func.inc");

## variable Initialization
os_arch = "";
key_list = "";
key = "";
appName = "";
kvircVer = "";
kvircPath = "";
exeName = "";
flag = 0;

## Get OS Architecture
os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

## Check for 32 bit platform
if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");

  key_list2 = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\");
}

## Check for 64 bit platform, only 32-bit application is present
else if("x64" >< os_arch)
{
  key_list =  make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");

  key_list2 = make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\");
}


if(isnull(key_list && key_list2)){
  exit(0);
}

foreach key(key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    kvircName = registry_get_sz(key:key + item, item:"DisplayName");

    ## Confirm application
    if("KVIrc" >< kvircName)
    {
      ## Grep Version from Registry
      kvircVer = eregmatch(pattern:"KVIrc ([0-9.]+)", string:kvircName);
      kvircPath = registry_get_sz(key:key + item, item:"UninstallString");
      kvircPath = "Unknown";

      if(kvircVer[1])
      {
        kvircVer = kvircVer[1];
      }
      else
      {
        foreach key1(key_list2)
        {
          # Grep Version from .EXE File
          Path = registry_get_sz(key:key1, item:"ProgramFilesDir");
          exePath = Path + "\kvirc";
          kvircVer = fetch_file_version(sysPath:exePath , file_name: "kvirc.exe");
          kvircPath = exePath ;

          if(!kvircVer)
          {
            # Taking Version From README File
            exePath = kvircPath + "\README.txt";

            share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exePath);
            file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:exePath);
            readmeText = read_file(share:share, file:file, offset:0, count:500);

            if(readmeText)
            {
              kvircVer = eregmatch(pattern:"Release ([0-9.]+)", string:readmeText);
              if(kvircVer){
                kvircVer = kvircVer[1];
              } else {
                continue;
              }
            }
          }
        }
      }
      # Set KB for KVIrc
      if(kvircVer != NULL)
      {
        set_kb_item(name:"Kvirc/Win/Ver", value:kvircVer);

        ## build cpe and store it as host_detail
        cpe = build_cpe(value:kvircVer, exp:"^([0-9.]+)", base:"cpe:/a:kvirc:kvirc:");
        if(isnull(cpe))
          cpe = "cpe:/a:kvirc:kvirc";

        register_product(cpe:cpe, location:kvircPath);

        log_message(data: build_detection_report(app: "KVIrc",
                                                 version: kvircVer,
                                                 install: kvircPath,
                                                 cpe: cpe,
                                                 concluded: kvircVer));
      }
    }
  }
}
