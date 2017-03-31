###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_microsoft_edge_detect.nasl 5351 2017-02-20 08:03:12Z mwiegand $
#
# Microsoft Edge Version Detection (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806184");
  script_version("$Revision: 5351 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-02-20 09:03:12 +0100 (Mon, 20 Feb 2017) $");
  script_tag(name:"creation_date", value:"2016-01-04 15:07:42 +0530 (Mon, 04 Jan 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Edge Version Detection (Windows)");
  script_tag(name:"summary" , value:"Detection of installed version of Microsoft Edge.

The script logs in via smb, detects the version of Microsoft Edge
on remote host and sets the KB.");
  script_summary("Check for Microsoft Edge version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl", "smb_registry_access.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");
include("version_func.inc");

## Variable Initialization
ver = "";
ieVer = "";
exePath = "";

## Function to Register Product and Build report
function build_report(app, ver, cpe, insloc)
{
  register_product(cpe:cpe, location:insloc);

  log_message(data: build_detection_report(app: app,
                                           version: ver,
                                           install: insloc,
                                           cpe: cpe,
                                           concluded: ver));
  exit(0);
}

# Get for Edge Installed Path
sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

sysPath = sysPath +"\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe";
file = "MicrosoftEdge.exe";

ver = fetch_file_version(sysPath, file_name:file);

## Set KB from Registry Entry version
if(ver != NULL)
{
  set_kb_item(name:"MS/Edge/Version", value:ver);
  set_kb_item(name:"MS/Edge/Installed", value:TRUE);

  ## Build CPE
  cpe = build_cpe(value:ver, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:edge:");
  if(isnull(cpe))
    cpe = "cpe:/a:microsoft:edge";

  ## Register Product and Build Report
  build_report(app: "Microsoft Edge", ver: ver, cpe: cpe, insloc: sysPath);
}
