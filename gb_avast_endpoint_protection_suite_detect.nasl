###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avast_endpoint_protection_suite_detect.nasl 4635 2016-11-28 08:14:54Z antu123 $
#
# Avast Endpoint Protection Suite Version Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.810216");
  script_version("$Revision: 4635 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-11-28 09:14:54 +0100 (Mon, 28 Nov 2016) $");
  script_tag(name:"creation_date", value:"2016-11-24 12:04:38 +0530 (Thu, 24 Nov 2016)");
  script_name("Avast Endpoint Protection Suite Version Detection");

  script_tag(name: "summary" , value: "Detection of installed version of
  Avast Endpoint Protection Suite. 
  The script logs in via smb, searches for string 'Avast Endpoint Protection
  Suite' in the registry and reads the version information from registry.");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl", "smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

## variable Initialization
os_arch = "";
avastPath = "";
avastName = "";
avastVer = "";
key = "";

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");
include("version_func.inc");

## Confirm HPE product
if(!registry_key_exists(key:"SOFTWARE\AVAST Software\Avast") &&
   !registry_key_exists(key:"SOFTWARE\Wow6432Node\AVAST Software\Avast")){
  exit(0);
}

## Get OS Architecture
os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(-1);
}

## Only 32-bit version is available
## Check for 32 bit platform
if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

## Check for 64 bit platform
else if("x64" >< os_arch){
  key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

##Iterate
foreach item (registry_enum_keys(key:key))
{
  avastName = registry_get_sz(key:key + item, item:"DisplayName");

  #### Confirm Application
  if(avastName =~ "avast! Endpoint Protection Suite$")
  {
    avastVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    avastPath = registry_get_sz(key:key + item, item:"InstallLocation");

    if(!avastPath){
      avastPath = "Couldn find the install location from registry";
    }

    if(avastVer)
    {
      set_kb_item(name:"Avast/Endpoint-Protection-Suite/Win/Ver", value:avastVer);

      ## build cpe and store it as host_detail
      cpe = build_cpe(value:avastVer, exp:"^([0-9.]+)", base:"cpe:/a:avast:endpoint_protection_suite:");
      if(isnull(cpe))
        cpe = "cpe:/a:avast:endpoint_protection_suite";

      ## Register Product and Build Report
      register_product(cpe:cpe, location:avastPath);

      log_message(data: build_detection_report(app: "Avast Endpoint Protection Suite",
                                               version: avastVer,
                                               install: avastPath,
                                               cpe: cpe,
                                               concluded: avastVer));
      exit(0);
    }
  }
}
