###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hpe_sap_business_suite_detect.nasl 7000 2017-08-24 11:51:46Z teissa $
#
# HPE Sizing Tool for SAP Business Suite Version Detection (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.809435");
  script_version("$Revision: 7000 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-08-24 13:51:46 +0200 (Thu, 24 Aug 2017) $");
  script_tag(name:"creation_date", value:"2016-10-17 16:22:36 +0530 (Mon, 17 Oct 2016)");
  script_name("HPE Sizing Tool for SAP Business Suite Version Detection (Windows)");

  script_tag(name: "summary" , value: "Detection of installed version of
  HPE Sizing Tool for SAP Business Suite.

  The script logs in via smb, searches for 'HPE Sizing Tool for SAP Business Suite'
  in the registry, gets version and installation path information from the registry.");

  script_tag(name:"qod_type", value:"registry");

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
os_arch = "";
hpPath = "";
hpName = "";
hpVer = "";
key = "";

## Confirm HPE product
if(!registry_key_exists(key:"SOFTWARE\Hewlett Packard Enterprise\Sizers\SAP HANA Sizing Tool") &&
   !registry_key_exists(key:"SOFTWARE\Wow6432Node\Hewlett Packard Enterprise\Sizers\SAP HANA Sizing Tool")){
  exit(0);
}

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
  if("HPE sizing tool for SAP Business Suite" >< hpName)
  {
    hpVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(hpVer)
    {
      hpPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!hpPath){
        hpPath = "Couldn find the install location from registry";
      }

      ## Set the version in KB
      set_kb_item(name:"HPE/Sizing/Tool/SAP/Sizing/Suite/Win/Ver", value:hpVer);

      ## build cpe and store it as host_detail
      cpe = build_cpe(value:hpVer, exp:"^([0-9.]+)", base:"cpe:/a:hp:sizing_tool_for_sap_business_suite_powered_by_hana:");
      if(isnull(cpe))
        cpe = "cpe:/a:hp:sizing_tool_for_sap_business_suite_powered_by_hana";

      ## Register Product and Build Report
      register_product(cpe:cpe, location:hpPath);

      log_message(data: build_detection_report(app: "HPE Sizing Tool for SAP Business Suite",
                                                 version: hpVer,
                                                 install: hpPath,
                                                 cpe: cpe,
                                                 concluded: hpVer));
    }
  }
}
