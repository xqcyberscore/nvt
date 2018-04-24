###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_iis_detect_win.nasl 9584 2018-04-24 10:34:07Z jschulte $
#
# Microsoft Internet Information Services (IIS) Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

tag_summary = "Detection of installed version of Internet Information Services (IIS).

The script logs in via smb, searches for Internet Information Services (IIS) in the
registry and gets the version from 'Version' string in registry";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802432";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 9584 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"last_modification", value:"$Date: 2018-04-24 12:34:07 +0200 (Tue, 24 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-05-14 15:41:01 +0530 (Mon, 14 May 2012)");
  script_name("Microsoft Internet Information Services (IIS) Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");

## Variable Initialization
key = "";
path = "";
cpe = "";
iisName = "";
iisVer = "";
iisVerString = "";


if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\InetStp";
if(!registry_key_exists(key:key)){
  exit(0);
}

iisName = registry_get_sz(key:key,  item:"ProductString");
if("Microsoft Internet Information Services" >< iisName)
{

  iisVer = registry_get_sz(key:key,  item:"VersionString");
  if(iisVer)
  {
    iisVerString = eregmatch(pattern:"Version ([0-9.]+)", string:iisVer);
    if(iisVerString[1])
    {
      set_kb_item(name:"MS/IIS/Ver", value:iisVerString[1]);
      path = registry_get_sz(key:key,  item:"InstallPath");
      if(!path){
        path = "Could not find the install path from registry";
      }

      cpe = build_cpe(value:iisVerString[1], exp:"^([0-9.]+)",
                      base:"cpe:/a:microsoft:iis:");
      if(!isnull(cpe))
        register_product(cpe:cpe, location:path);

      log_message(data: build_detection_report(app:"Microsoft Internet" +
                  " Information Services", version:iisVerString[1], install: path,
                  cpe:cpe, concluded:iisVerString[1]));
    }
  }
}
