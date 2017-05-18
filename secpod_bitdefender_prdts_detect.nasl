###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_bitdefender_prdts_detect.nasl 5871 2017-04-05 13:33:48Z antu123 $
#
# BitDefender Product(s) Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2014-05-21
# Updated according to CR57 and to support 32 and 64 bit.
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
  script_oid("1.3.6.1.4.1.25623.1.0.900326");
  script_version("$Revision: 5871 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-04-05 15:33:48 +0200 (Wed, 05 Apr 2017) $");
  script_tag(name:"creation_date", value:"2009-03-20 07:08:52 +0100 (Fri, 20 Mar 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("BitDefender Product(s) Version Detection");

  tag_summary =
"Detection of installed version of BitDefender Product(s) on Windows.

The script logs in via smb, searches for BitDefender Product(s) in the
registry and gets the version.";


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
bitName = "";
bitVer = "";
insLoc = "";

## Check the product Existence
key = "SOFTWARE\BitDefender";
if(!registry_key_exists(key:key))
{
  key = "SOFTWARE\Wow6432Node\BitDefender";
  if(!registry_key_exists(key:key)){
    exit(0);
  }
}

## Get OS Architecture
os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

## Check for 32 bit platform
if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\BitDefender\About\");
}

## Check for 64 bit platform
else if("x64" >< os_arch)
{
  key_list =  make_list("SOFTWARE\BitDefender\About\",
                        "SOFTWARE\Wow6432Node\BitDefender\About\");
}

foreach bitKey (key_list)
{
  bitName = registry_get_sz(key:bitKey, item:"ProductName");

  ## Check for BitDefender Internet Security
  if("bitdefender internet security" >< tolower(bitName))
  {
    bitVer = registry_get_sz(key:bitKey, item:"ProductVersion");

    if(bitVer == NULL)
    {
      if("Wow6432Node" >< bitKey){
        key = "SOFTWARE\Wow6432Node\BitDefender\BitDefender Desktop\Maintenance\InternetSecurity";
      } else {
        key = "SOFTWARE\BitDefender\BitDefender Desktop\Maintenance\InternetSecurity";
      }

      bitVer = registry_get_sz(key:key, item:"ProductVersion");
    }

    if(bitVer)
    {
      insLoc = registry_get_sz(key:bitKey - 'About\\', item:"InstallDir");
      if(!insLoc){
        insLoc = "Could not find the install Location from registry";
      }

      set_kb_item(name:"BitDefender/InetSec/Ver", value:bitVer);

      ## build cpe
      cpe = build_cpe(value:bitVer, exp:"^([0-9.]+)", base:"cpe:/a:bitdefender:internet_security:");
      if(isnull(cpe))
        cpe = "cpe:/a:bitdefender:internet_security";

      build_report(app:bitName, ver:bitVer, cpe:cpe, insloc:insLoc, concluded:bitVer);

      ## Register for 64 bit app on 64 bit OS once again
      if("64" >< os_arch && "Wow6432Node" >!< bitKey)
      {
        set_kb_item(name:"BitDefender64/InetSec/Ver", value:bitVer);

        ## Build CPE
        cpe = build_cpe(value:bitVer, exp:"^([0-9.]+)", base:"cpe:/a:bitdefender:internet_security:x64:");
        if(isnull(cpe))
          cpe = "cpe:/a:bitdefender:internet_security:x64";

        build_report(app:bitName, ver:bitVer, cpe:cpe, insloc:insLoc, concluded:bitVer);
      }
    }
  }

  ## Check for BitDefender Antivirus
  if("bitdefender antivirus" >< tolower(bitName))
  {
    bitVer = registry_get_sz(key:bitKey, item:"ProductVersion");

    if(bitVer == NULL)
    {
      if("Wow6432Node" >< bitKey){
        key = "SOFTWARE\Wow6432Node\BitDefender\BitDefender Desktop\Maintenance\Antivirus";
      } else {
        key = "SOFTWARE\BitDefender\BitDefender Desktop\Maintenance\Antivirus";
      }

      bitVer = registry_get_sz(key:key, item:"ProductVersion");
    }

    if(bitVer)
    {
      insLoc = registry_get_sz(key:bitKey - 'About\\', item:"InstallDir");
      if(!insLoc){
        insLoc = "Could not find the install Location from registry";
      }

      set_kb_item(name:"BitDefender/AV/Ver", value:bitVer);

      ## build cpe
      cpe = build_cpe(value:bitVer, exp:"^([0-9.]+)", base:"cpe:/a:bitdefender:bitdefender_antivirus:");
      if(isnull(cpe))
        cpe = "cpe:/a:bitdefender:bitdefender_antivirus";

      build_report(app:bitName, ver:bitVer, cpe:cpe, insloc:insLoc, concluded:bitVer);

      ## Register for 64 bit app on 64 bit OS once again
      if("64" >< os_arch && "Wow6432Node" >!< bitKey)
      {
        set_kb_item(name:"BitDefender64/AV/Ver", value:bitVer);

        ## Build CPE
        cpe = build_cpe(value:bitVer, exp:"^([0-9.]+)", base:"cpe:/a:bitdefender:bitdefender_antivirus:x64:");
        if(isnull(cpe))
          cpe = "cpe:/a:bitdefender:bitdefender_antivirus:x64";

        build_report(app:bitName, ver:bitVer, cpe:cpe, insloc:insLoc, concluded:bitVer);
      }
    }
  }
}
