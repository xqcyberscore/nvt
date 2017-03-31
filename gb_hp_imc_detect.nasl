###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_imc_detect.nasl 4141 2016-09-23 11:27:20Z antu123 $
#
# HP Intelligent Management Center (iMC) Version Detection (Windows)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.809282");
  script_version("$Revision: 4141 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-09-23 13:27:20 +0200 (Fri, 23 Sep 2016) $");
  script_tag(name:"creation_date", value:"2016-09-22 16:43:00 +0530 (Thu, 22 Sep 2016)");
  script_name("HP Intelligent Management Center (iMC) Version Detection (Windows)");

  script_tag(name: "summary" , value: "Detection of installed version of
  HP Intelligent Management Center (iMC).

  The script logs in via smb, searches for 'HP Intelligent Management Center' in the
  registry, gets version and installation path information from the registry.");

  script_tag(name:"qod_type", value:"registry");

  script_summary("Detection of installed version of HP Intelligent Management Center");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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
hpPath = "";
hpName = "";
hpVer = "";
key = "";

## Get OS Architecture
os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

##Key based on architecture
if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

# Check for 64 bit platform, Currently only 32-bit application is available
else if("x64" >< os_arch){
  key =  "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

foreach item (registry_enum_keys(key:key))
{
  hpName = registry_get_sz(key:key + item, item:"DisplayName");

  ## Confirm the application
  if("HP Intelligent Management Center" >< hpName)
  {
    hpVer = registry_get_sz(key:key + item, item:"DisplayVersion");

    if(hpVer)
    {
      hpPath = registry_get_sz(key:key + item, item:"UninstallString");
      hpPath = eregmatch(pattern:".*.exe", string:hpPath);
      if(!hpPath){
        hpPath = "Couldn find the install location from registry";
      }

      hpVer = ereg_replace(pattern:" ", string:hpVer, replace: ".");

      ## Set the version in KB
      set_kb_item(name:"HPE/iMC/Win/Ver", value:hpVer);

      ## build cpe and store it as host_detail
      cpe = build_cpe(value:hpVer, exp:"([0-9A-Z. ]+)", base:"cpe:/a:hp:intelligent_management_center:");
      if(isnull(cpe))
        cpe = "cpe:/a:hp:intelligent_management_center";

      ## Register Product and Build Report
      register_product(cpe:cpe, location:hpPath[0]);

      log_message(data: build_detection_report(app: "HP Intelligent Management Center",
                                               version: hpVer,
                                               install: hpPath[0],
                                               cpe: cpe,
                                               concluded: hpVer));
      exit(0);
    }
  }
}
