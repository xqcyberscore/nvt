###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_win_live_messenger_detect.nasl 7582 2017-10-26 11:56:51Z cfischer $
#
# Microsoft Windows Live Messenger Client Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# Update to detect the Messenger Plus! Live
#  - By Sharath S <sharaths@secpod.com> on 2009-07-31
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
  script_oid("1.3.6.1.4.1.25623.1.0.800331");
  script_version("$Revision: 7582 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 13:56:51 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2009-01-08 07:43:30 +0100 (Thu, 08 Jan 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Microsoft Windows Live Messenger Client Version Detection");

tag_summary =
"Detection of installed version of Microsoft Windows Live Messenger.

The script logs in via smb, searches for Microsoft Windows Live Messenger
in the registry and gets the version from registry.";


  script_tag(name : "summary" , value : tag_summary);

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl", "smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("version_func.inc");
include("host_details.inc");

osArch = "";
key_list = "";
appName = "";
appLoc = "";
livemgrVer = "";
msgPlusVer  = "";

## start script
if(!get_kb_item("SMB/WindowsVersion"))
{
  exit(-1);
}

osArch = get_kb_item("SMB/Windows/Arch");
if(!osArch)
{
  exit(0);
}

## if os is 32 bit iterate over comman path
if("x86" >< osArch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

## Check for 64 bit platform
else if("x64" >< osArch){
 key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                      "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

checkduplicate = "";
checkduplicate_path = "";

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    appName = registry_get_sz(key:key + item, item:"DisplayName");

    # Windows Live Messenger
    if("Windows Live Messenger" >< appName)
    {
      livemgrVer = registry_get_sz(key:key + item, item:"DisplayVersion");

      appLoc = registry_get_sz(key:key + item, item:"InstallLocation"); 
      if(!appLoc){
        appLoc = "Couldn find the install location from registry";
      }
      
      if(livemgrVer)
      {
        ## Check if version is already set
        if (livemgrVer + ", " >< checkduplicate && appLoc + ", " >< checkduplicate_path){
          continue;
        }
        ##Assign detected version value to checkduplicate so as to check in next loop iteration
        checkduplicate  += livemgrVer + ", ";
        checkduplicate_path += appLoc + ", ";
 
        # Set KB for Windows Live Messenger
        set_kb_item(name:"MS/LiveMessenger/Ver", value:livemgrVer);
 
        cpe = build_cpe(value:livemgrVer, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:windows_live_messenger:");
        if(isnull(cpe))
          cpe = "cpe:/a:microsoft:windows_live_messenger";

        ## 64 bit apps on 64 bit platform
        if("x64" >< osArch && "Wow6432Node" >!< key)
        {
          set_kb_item(name:"MS/LiveMessenger64/Ver", value:livemgrVer);

          cpe = build_cpe(value:livemgrVer, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:windows_live_messenger:x64:");
          if(isnull(cpe))
            cpe = "cpe:/a:microsoft:windows_live_messenger:x64";
        }
        ## Register Product and Build Report
        build_report(app: appName, ver:livemgrVer, cpe:cpe, insloc:appLoc);
      }
    }

    # Messenger Plus! 
    if("Messenger Plus!" >< appName)
    {
      msgPlusVer = registry_get_sz(key:key + item, item:"DisplayVersion");
      plusPath = registry_get_sz(key:key + item, item:"UninstallString");
      plusPath = eregmatch(pattern:'"(.*)"', string:plusPath);

      if(isnull(msgPlusVer) && plusPath[1])
      {
        file = plusPath[1];
        if("Uninstall.exe" >< file)
        {
          file -= "Uninstall.exe";
          msgPlusVer =  fetch_file_version(sysPath:file, file_name:"MPTools.exe");

          if(!msgPlusVer){
            msgPlusVer = fetch_file_version(sysPath:file, file_name:"WinksViewer.exe");
          }
        }
        else if("MsgPlus.exe" >< file)
        {
          file -= "MsgPlus.exe";
          msgPlusVer = fetch_file_version(sysPath:file, file_name:"MsgPlus.exe");
        }  
      }

      # Set KB for Version and Path of Messenger Plus!
      if(!isnull(msgPlusVer))
      {
        set_kb_item(name:"MS/MessengerPlus/Ver", value:msgPlusVer);
        set_kb_item(name:"MS/MessengerPlus/Path", value:plusPath[1]);
      
        # Set KB for Windows Live Messenger Plus!
        cpe = build_cpe(value:msgPlusVer, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:messenger_plus%21_live:");
        if(isnull(cpe))
          cpe = "cpe:/a:microsoft:messenger_plus%21_live";

        ## 64 bit apps on 64 bit platform
        if("x64" >< osArch && "Wow6432Node" >!< key)
        {
          set_kb_item(name:"MS/MessengerPlus64/Ver", value:msgPlusVer);

          cpe = build_cpe(value:msgPlusVer, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:messenger_plus%21_live:x64:");
          if(isnull(cpe))
            cpe = "cpe:/a:microsoft:messenger_plus%21_live:x64:";
        }
        ## Register Product and Build Report
        build_report(app: appName, ver:msgPlusVer, cpe:cpe, insloc:plusPath[1]);
      }
    }
  }
}
