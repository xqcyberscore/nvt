###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_tsm_fastback_detect.nasl 6040 2017-04-27 09:02:38Z teissa $
#
# IBM Tivoli Storage Manager FastBack Version Detection (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805598");
  script_version("$Revision: 6040 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-04-27 11:02:38 +0200 (Thu, 27 Apr 2017) $");
  script_tag(name:"creation_date", value:"2015-07-02 15:00:07 +0530 (Thu, 02 Jul 2015)");
  script_name("IBM Tivoli Storage Manager FastBack Version Detection (Windows)");

  script_tag(name: "summary" , value: "Detection of installed version of
  IBM Tivoli Storage Manager FastBack.

  The script logs in via smb, searches for 'IBM Tivoli Storage Manager FastBack'
  string in the registry and gets the version from registry.");


  script_tag(name:"qod_type", value:"executable_version");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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
key = "";
tivPath = "";
tivVer = "";
tivName = "";

## Key is same for 32 bit and 64 bit platform 
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

##Iterate
foreach item (registry_enum_keys(key:key))
{
  tivName = registry_get_sz(key:key + item, item:"DisplayName");

  #### Confirm Application
  if("IBM Tivoli Storage Manager FastBack" >< tivName)
  {
    tivPath = registry_get_sz(key:key + item, item:"InstallLocation");
    if(tivPath)
    {
      ##try to get product version from FastBackMount.exe file
      tivPath1 = tivPath + "mount\FastBackMount.exe";

      ##Fetch Product Version from FastBackMount.exe file
      tivVer = GetVersionFromFile(file: tivPath1, verstr:"prod");
      if(!tivVer)
      {
         ##Try to get product version from alternate file
         tivPath1 = tivPath + "common\contain.exe" ;

         ##Fetch Product Version from FastBackMount.exe file
         tivVer = GetVersionFromFile(file: tivPath1, verstr:"prod");
      }
    }

    ##If version is available
    if(tivVer)
    {
      set_kb_item(name:"IBM/Tivoli/Storage/Manager/FastBack/Win/Ver", value:tivVer);

      ## build cpe and store it as host_detail
      cpe = build_cpe(value:tivVer, exp:"^([0-9.]+)", base:"cpe:/a:ibm:tivoli_storage_manager_fastback:");
      if(isnull(cpe))
        cpe = "cpe:/a:ibm:tivoli_storage_manager_fastback";

      ## Register for 64 bit app on 64 bit OS once again
      if("64" >< os_arch)
      {
        set_kb_item(name:"IBM/Tivoli/Storage/Manager/FastBack/Win64/Ver", value:tivVer);

        ## Build CPE
        cpe = build_cpe(value:tivVer, exp:"^([0-9.]+)", base:"cpe:/a:ibm:tivoli_storage_manager_fastback:x64:");

        if(isnull(cpe))
          cpe = "cpe:/a:ibm:tivoli_storage_manager_fastback:x64";
      }
      ##register cpe
      register_product(cpe:cpe, location:tivPath);
      log_message(data: build_detection_report(app: tivName,
                                               version: tivVer,
                                               install: tivPath,
                                               cpe: cpe,
                                               concluded: tivVer));
      exit(0);
    }
  }
}
