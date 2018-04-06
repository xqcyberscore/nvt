##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_magic_iso_maker_detect.nasl 9347 2018-04-06 06:58:53Z cfischer $
#
# Magic ISO Maker Version Detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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

tag_summary = "This script finds the installed version of Magic ISO Maker
  and sets the result in KB.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800272");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 9347 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 08:58:53 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-04-13 15:50:35 +0200 (Mon, 13 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Magic ISO Maker Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name: "qod_type", value: "registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Service detection");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800272";
SCRIPT_DESC = "Magic ISO Maker Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  name = registry_get_sz(key:key + item, item:"DisplayName");
  if("Magic ISO Maker" >< name)
  {
    ver = eregmatch(pattern:"v([0-9.]+) \(build ([0-9]{3,})\)", string:name);
    if((ver[1] != NULL && ver[2] != NULL))
    {
      tmp_version = ver[1] + "." + ver[2];
      set_kb_item(name:"MagicISOMaker/Ver", value:tmp_version);
      log_message(data:"Magic ISO Maker version " + ver[1] + "." + ver[2] +
                      " was detected on the host");
     
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:tmp_version, exp:"^([0-9]\.[0-9])", base:"cpe:/a:magic_iso_maker:magic_iso_maker:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
    exit(0);
  }
}
