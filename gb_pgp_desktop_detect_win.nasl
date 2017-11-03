###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pgp_desktop_detect_win.nasl 7628 2017-11-02 12:00:39Z santu $
#
# Symantec PGP/Encryption Desktop Version Detection (Windows)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright (C) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2013-09-04
# According to CR57, new style script_tags and to detect
# Symantec Encryption Desktop Version.
#
# Updated By: Shakeel <bshakeel@secpod.com> on 2014-06-26
# According to CR57 and to support 32 and 64 bit.
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
  script_oid("1.3.6.1.4.1.25623.1.0.800215");
  script_version("$Revision: 7628 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-11-02 13:00:39 +0100 (Thu, 02 Nov 2017) $");
  script_tag(name:"creation_date", value:"2009-01-06 15:38:06 +0100 (Tue, 06 Jan 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Symantec PGP/Encryption Desktop Version Detection (Windows)");

  tag_summary =
"Detection of installed version of Symantec PGP/Encryption Desktop on Windows.

The script logs in via smb, search for the product name in the registry, gets
version from the 'DisplayVersion' string and set it in the KB item.";


  script_tag(name : "summary" , value : tag_summary);

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
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

## variable initialization
os_arch = "";
key_list = "";
key= "";
appName = "";
insloc = "";
pgpdeskVer = "";

## Get OS Architecture
os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(-1);
}


##32-bit application cannot be installed on 64-bit OS
key =  "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

## Confirm Application
if(!registry_key_exists(key:"SOFTWARE\PGP Corporation\PGP")){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  appName = registry_get_sz(key:key + item, item:"DisplayName");

  if("PGP Desktop" >< appName || "Symantec Encryption Desktop" >< appName)
  {
    ## Get the Installed Path
    insloc = registry_get_sz(key:key + item, item:"InstallLocation");
    if(!insloc){
      insloc = "Could not find the install location from registry";
    }

    ## Get the version
    deskVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(!deskVer) exit(0);

    if("PGP Desktop" >< appName)
    {
      replace_kb_item(name:"PGPDesktop_or_EncryptionDesktop/Win/Installed", value:TRUE);
      set_kb_item(name:"PGPDesktop/Win/Ver", value:deskVer);

      ## build cpe and store it as host_detail
      cpe = build_cpe(value:deskVer, exp:"^([0-9.]+)", base:"cpe:/a:symantec:pgp_desktop:");
      if(isnull(cpe))
        cpe = "cpe:/a:symantec:pgp_desktop";

      build_report(app: appName, ver: deskVer, cpe: cpe, insloc: insloc);

      ## 64 bit apps on 64 bit platform
      if("x64" >< os_arch)
      {
        replace_kb_item(name:"PGPDesktop_or_EncryptionDesktop/Win/Installed", value:TRUE);
        set_kb_item(name:"PGPDesktop64/Win/Ver", value:deskVer);

        ## build cpe and store it as host_detail
        cpe = build_cpe(value:deskVer, exp:"^([0-9.]+)", base:"cpe:/a:symantec:pgp_desktop:x64:");
        if(isnull(cpe))
          cpe = "cpe:/a:symantec:pgp_desktop:x64";

        ## Register Product and Build Report
        build_report(app: appName, ver: deskVer, cpe: cpe, insloc: insloc);
      }
    }
    else
    {
      replace_kb_item(name:"PGPDesktop_or_EncryptionDesktop/Win/Installed", value:TRUE);
      set_kb_item(name:"EncryptionDesktop/Win/Ver", value:deskVer);

      ## build cpe and store it as host_detail
      cpe = build_cpe(value:deskVer, exp:"^([0-9.]+)", base:"cpe:/a:symantec:encryption_desktop:");
      if(isnull(cpe))
        cpe = "cpe:/a:symantec:encryption_desktop";

      build_report(app: appName, ver: deskVer, cpe: cpe, insloc: insloc);

      ## 64 bit apps on 64 bit platform
      if("x64" >< os_arch)
      {
        replace_kb_item(name:"PGPDesktop_or_EncryptionDesktop/Win/Installed", value:TRUE);
        set_kb_item(name:"EncryptionDesktop64/Win/Ver", value:deskVer);

        ## build cpe and store it as host_detail
        cpe = build_cpe(value:deskVer, exp:"^([0-9.]+)", base:"cpe:/a:symantec:encryption_desktop:x64:");
        if(isnull(cpe))
          cpe = "cpe:/a:symantec:encryption_desktop:x64";

        ## Register Product and Build Report
        build_report(app: appName, ver: deskVer, cpe: cpe, insloc: insloc);
      }
    }
  }
}
