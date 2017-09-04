###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_gzip_detect_win.nasl 7000 2017-08-24 11:51:46Z teissa $
#
# GZip Version Detection (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2014-05-27
# Updated according to CR57 and to support 32 and 64 bit.
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800451");
  script_version("$Revision: 7000 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-08-24 13:51:46 +0200 (Thu, 24 Aug 2017) $");
  script_tag(name:"creation_date", value:"2010-02-04 12:53:38 +0100 (Thu, 04 Feb 2010)");
  script_tag(name:"qod_type", value:"registry");
  script_name("GZip Version Detection (Windows)");

  tag_summary =
"Detection of installed version of GZip on Windows.

The script logs in via smb, searches for GZip in the registry
and gets the version from the registry.";


  script_tag(name : "summary" , value : tag_summary);
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
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
gzipName = "";
gzipVer = "";
appPath = "";

if(!registry_key_exists(key:"SOFTWARE\GnuWin32\Gzip"))
{
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\GnuWin32\Gzip")){
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
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

## Presently Gzip Wizard 64bit application is not available
## Check for 32 bit App on 64 bit platform
else if("x64" >< os_arch){
  key =  "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  gzipName = registry_get_sz(key:key + item, item:"DisplayName");

  if(" Gzip" >< gzipName)
  {
    gzipVer = registry_get_sz(key:key + item, item:"DisplayVersion");

    if(gzipName != NULL)
    {
      appPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!appPath){
        appPath = "Could not find the install Location from registry";
      }

      gzipVer = ereg_replace(pattern:"-", string:gzipVer, replace: ".");
      set_kb_item(name:"GZip/Win/Ver", value:gzipVer);

      ## build cpe and store it as host_detail
      cpe = build_cpe(value:gzipVer, exp:"^([0-9.]+)", base:"cpe:/a:gnu:gzip:");
      if(isnull(cpe))
        cpe = "cpe:/a:gnu:gzip";

      register_product(cpe:cpe, location:appPath);

      log_message(data: build_detection_report(app: gzipName,
                                               version: gzipVer,
                                               install: appPath,
                                               cpe: cpe,
                                               concluded: gzipName));
    }
  }
}
