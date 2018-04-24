###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_professional_detect_win.nasl 9584 2018-04-24 10:34:07Z jschulte $
#
# Adobe Flash Professional Detection (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_summary = "Detection of installed version of Adobe Flash Professional.

The script logs in via smb, searches for Adobe Flash Professional in the
registry and gets the version from 'Version' string in registry";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802778";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 9584 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"last_modification", value:"$Date: 2018-04-24 12:34:07 +0200 (Tue, 24 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-05-15 12:12:47 +0530 (Tue, 15 May 2012)");
  script_name("Adobe Flash Professional Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

## Variable Initialization
appkey = "";
key = "";
appPath = "";
flashName = "";
ver = "";
flashVer = "";
cpe = "";

## Confirm application is installed
appkey = "SOFTWARE\Adobe\Flash";
if(!registry_key_exists(key:appkey)) {
    exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  flashName = registry_get_sz(key:key + item, item:"DisplayName");
  if(!egrep(pattern:"Adobe Flash CS([0-9.]+) Professional", string:flashName)){
    continue;
  }

  flashVer = registry_get_sz(key:key + item, item:"DisplayVersion");
  if(flashVer)
  {
    ver = eregmatch(pattern:"CS([0-9.]+)", string:flashName);
    if(ver)
    {
      version = ver[0] + " " + flashVer;

      ## Set the KB item
      set_kb_item(name:"Adobe/Flash/Prof/Win/Ver", value:version);
      cpe = build_cpe(value:flashVer, exp:"^([0-9.]+)", base:"cpe:/a:adobe:flash_cs" + ver[1] + ":");

      path = "Could not find the install location from registry";
      if(!isnull(cpe))
        register_product(cpe:cpe, location:path);

      log_message(data: build_detection_report(app:"Adobe Flash Professional",
                                         version:version,
                                         install:path,
                                         cpe:cpe,
                                         concluded: version));
    }
  }
}
