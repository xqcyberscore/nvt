###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_workspace_streaming_detect.nasl 5499 2017-03-06 13:06:09Z teissa $
#
# Symantec Workspace Streaming (SWS) Agent Version Detection (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.805541");
  script_version("$Revision: 5499 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-03-06 14:06:09 +0100 (Mon, 06 Mar 2017) $");
  script_tag(name:"creation_date", value:"2015-04-28 18:51:34 +0530 (Tue, 28 Apr 2015)");
  script_name("Symantec Workspace Streaming (SWS) Agent Version Detection (Windows)");

  script_tag(name: "summary" , value: "Detection of installed version of
  Symantec Workspace Streaming Agent.

  The script logs in via smb, searches for 'Symantec Workspace Streaming Agent'
  in the registry and gets the version from registry.");

  script_tag(name:"qod_type", value:"registry");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl", "smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

# Function to Register Product and Build report
function build_report(app, ver, cpe, insloc)
{
  register_product(cpe:cpe, location:insloc);
  log_message(data: build_detection_report(app: app,
                                           version: ver,
                                           install: insloc,
                                           cpe: cpe,
                                           concluded: ver));
}

## variable Initialization
os_arch = "";
key = "";
agentPath = "";
symVer = "";
agentName = "";

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");
include("version_func.inc");


## Get OS Architecture
os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

## Key is same for 32 bit and 64 bit platform 
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

##Iterate
foreach item (registry_enum_keys(key:key))
{
  agentName = registry_get_sz(key:key + item, item:"DisplayName");

  #### Confirm Application
  if("Symantec Workspace Streaming Agent" >< agentName)
  {
    agentVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    agentPath = registry_get_sz(key:key + item, item:"InstallLocation");
    if(!agentPath)
    {
      agentPath = registry_get_sz(key:key + item, item:"InstallSource");
      if(!agentPath){
        agentPath = "Couldn find the install location from registry";
      }
    }

    if(agentVer)
    {
      set_kb_item(name:"Symantec/Workspace/Streaming/Agent/Win/Ver", value:agentVer);

    ## build cpe and store it as host_detail
      cpe = build_cpe(value:agentVer, exp:"^([0-9.]+)", base:"cpe:/a:symantec:workspace_streaming:");
      if(isnull(cpe))
        cpe = "cpe:/a:symantec:workspace_streaming";

      ## Register for 64 bit app on 64 bit OS once again
      if("64" >< os_arch)
      {
        set_kb_item(name:"Symantec/Workspace/Streaming/Agent/Win64/Ver", value:agentVer);

        ## Build CPE
        cpe = build_cpe(value:agentVer, exp:"^([0-9.]+)", base:"cpe:/a:symantec:workspace_streaming:x64:");

        if(isnull(cpe))
          cpe = "cpe:/a:symantec:workspace_streaming:x64";
      }

      ## Register Product and Build Report
      build_report(app:agentName, ver:agentVer, cpe:cpe, insloc:agentPath);
    }
    exit(0);
  }
}
