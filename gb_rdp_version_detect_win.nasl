###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_rdp_version_detect_win.nasl 3869 2016-08-23 07:14:02Z antu123 $
#
# Microsoft Remote Desktop Protocol Version Detection (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.808281");
  script_version("$Revision: 3869 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-08-23 09:14:02 +0200 (Tue, 23 Aug 2016) $");
  script_tag(name:"creation_date", value:"2016-08-03 17:52:03 +0530 (Wed, 03 Aug 2016)");
  script_name("Microsoft Remote Desktop Protocol Version Detection (Windows)");

  script_tag(name: "summary" , value: "Detection of installed version of
  Remote Desktop Protocol.

  The script logs in via smb and check the version of mstscax.dll file.");

  script_tag(name:"qod_type", value:"executable_version");
  script_summary("Set version of 'mstscax.dll' file in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");
include("version_func.inc");

## Function to Register Product and Build report
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
sysPath = "";

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Get Mstscax.dll file version
rdpVer = fetch_file_version(sysPath, file_name:"system32\Mstscax.dll");

if(rdpVer)
{
  rdpPath = sysPath + "\System32\Mstscax.dll";

  ## Set kb
  set_kb_item(name:"remote/desktop/protocol/Win/Ver", value:rdpVer);

  ## build cpe and store it as host_detail
  cpe = build_cpe(value:rdpVer, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:rdp:");
  if(isnull(cpe))
    cpe = "cpe:/a:microsoft:rdp";

  ## Register Product and Build Report
  build_report(app:"Microsoft Remote Desktop Protocol", ver:rdpVer, cpe:cpe, insloc:rdpPath);
}
