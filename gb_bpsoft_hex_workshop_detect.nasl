###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bpsoft_hex_workshop_detect.nasl 9347 2018-04-06 06:58:53Z cfischer $
#
# BreakPoint Software, Hex Workshop Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_summary = "This script finds the installed Hex Workshop Version and saves the
  version in KB.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800326");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 9347 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 08:58:53 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-01-06 15:38:06 +0100 (Tue, 06 Jan 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("BreakPoint Software Hex Workshop Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800326";
SCRIPT_DESC = "BreakPoint Software Hex Workshop Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  if("Hex Workshop" >< registry_get_sz(key:key + item, item:"DisplayName"))
  {
    hwVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(hwVer)
    {
      # Set the Version in KB
      set_kb_item(name:"BPSoft/HexWorkshop/Ver", value:hwVer);
      log_message(data:"BPSoft HexWork shop version " + hwVer + " was" + 
                         " detected on the host");
    
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:hwVer, exp:"^([0-9.]+)", base:"cpe:/a:bpsoft:hex_workshop:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
    exit(0);
  }
}
