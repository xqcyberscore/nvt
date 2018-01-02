###############################################################################
# OpenVAS Vulnerability Test
# $Id: sophos_installed.nasl 8208 2017-12-21 07:33:41Z cfischer $
#
# Sophos Anti Virus Check
#
# Authors:
# Jason Haar <Jason.Haar@trimble.co.nz>
#
# Copyright:
# Copyright (C) 2004 Jason Haar
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12215");
  script_version("$Revision: 8208 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-12-21 08:33:41 +0100 (Thu, 21 Dec 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Sophos Anti Virus Check");

  script_tag(name: "summary" , value: "This plugin checks that the remote host
  has the Sophos Antivirus installed and that it is running.

  The script logs in via smb, searches for Sophos Antivirus in the registry
  and gets the version from 'DisplayVersion' string from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 Jason Haar");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl", "smb_reg_service_pack.nasl", "smb_enum_services.nasl");
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
sophosPath = "";
sophosVer = "";
sophosName = "";

services = get_kb_item("SMB/svcs");

version = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Sophos/SweepNT/Version");
if(!version)
{
  ## Get OS Architecture
  os_arch = get_kb_item("SMB/Windows/Arch");

  ## Check for 32 bit platform
  if("x86" >< os_arch){
    key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
  }

  ## Check for 64 bit platform
  ## 64 bit App is not available
  else if("x64" >< os_arch){
    key =  "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
  }

  if(isnull(key)){
    exit(0);
  }

  foreach item (registry_enum_keys(key:key))
  {
    sophosName = registry_get_sz(key:key + item, item:"DisplayName");

    ## Confirm application
    if("Sophos Anti-Virus" >< sophosName)
    {
      sophosVer = registry_get_sz(key:key + item, item:"DisplayVersion");

      sophosPath = registry_get_sz(key:key + item, item:"InstallLocation");
      if(!sophosPath){
        sophosPath = "Unable to find the install location from registry";
      }

      if(sophosVer)
      {
        set_kb_item(name:"Sophos/Anti-Virus/Win/Installed", value:TRUE);
        set_kb_item(name:"Sophos/Anti-Virus/Win/Ver", value:sophosVer);
        register_and_report_cpe( app:"Sophos Anti-Virus", ver:sophosVer, base:"cpe:/a:sophos:anti-virus:", expr:"^([0-9.]+)", insloc:sophosPath );
      }
    }
  }
}


# Checks to see if the service is running
if((version || sophosVer) && services)
{
  if("[SWEEPSRV]" >!< services)
  {
    report = "
    The remote host has the Sophos antivirus installed, but it
    is not running.

    As a result, the remote host might be infected by viruses received by
    email or other means.

    Solution: Enable the remote AntiVirus and configure it to check for
    updates regularly.";
    log_message(data:report);
  }
}
