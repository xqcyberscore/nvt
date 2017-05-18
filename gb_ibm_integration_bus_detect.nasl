###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_integration_bus_detect.nasl 5693 2017-03-23 12:15:24Z antu123 $
#
# IBM Integration Bus Version Detection (Windows)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.810801");
  script_version("$Revision: 5693 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-03-23 13:15:24 +0100 (Thu, 23 Mar 2017) $");
  script_tag(name:"creation_date", value:"2017-03-23 16:40:33 +0530 (Thu, 23 Mar 2017)");
  script_name("IBM Integration Bus Version Detection (Windows)");

  script_tag(name: "summary" , value: "Detection of installed version of IBM
  Integration Bus.

  The script logs in via smb, searches for 'IBM Integration Bus' string in the
  registry and gets the version from registry.");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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
key = "";
ibPath = "";
ibVer = "";
ibName = "";

## Get OS Architecture
os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

##Check application is installed
if(!registry_key_exists(key:"SOFTWARE\IBM\IBM Integration Bus")){
  exit(0);
}

## Key is same for 32 bit and 64 bit platform 
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

##Iterate
foreach item (registry_enum_keys(key:key))
{
  ibName = registry_get_sz(key:key + item, item:"DisplayName");

  #### Confirm Application
  if("IBM Integration Bus" >< ibName)
  {
    ibPath = registry_get_sz(key:key + item, item:"InstallLocation");
    if(!ibPath){
      ibPath = "Couldn find the install location from registry";
    }
  
    ibVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    ##If version is available
    if(ibVer)
    {
      set_kb_item(name:"IBM/Integration/Bus/Win/Ver", value:ibVer);

      ## build cpe and store it as host_detail
      cpe = build_cpe(value:ibVer, exp:"^([0-9.]+)", base:"cpe:/a:ibm:integration_bus:");
      if(isnull(cpe))
        cpe = "cpe:/a:ibm:integration_bus";

      ## Register for 64 bit app on 64 bit OS once again
      if("64" >< os_arch)
      {
        set_kb_item(name:"IBM/Integration/Bus/Win64/Ver", value:ibVer);

        ## Build CPE
        cpe = build_cpe(value:ibVer, exp:"^([0-9.]+)", base:"cpe:/a:ibm:integration_bus:x64:");

        if(isnull(cpe))
          cpe = "cpe:/a:ibm:integration_bus:x64";
      }
      ##register cpe
      register_product(cpe:cpe, location:ibPath);
      log_message(data: build_detection_report(app: ibName,
                                               version: ibVer,
                                               install: ibPath,
                                               cpe: cpe,
                                               concluded: ibVer));
      exit(0);
    }
  }
}
