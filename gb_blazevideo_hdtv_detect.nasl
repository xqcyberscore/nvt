###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_blazevideo_hdtv_detect.nasl 8528 2018-01-25 07:57:36Z teissa $
#
# Blazevideo HDTV Player Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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

tag_summary = "This script detects the version of Blazevideo HDTV Player
  and sets the version in KB.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800512");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 8528 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-25 08:57:36 +0100 (Thu, 25 Jan 2018) $");
  script_tag(name:"creation_date", value:"2009-02-13 14:28:43 +0100 (Fri, 13 Feb 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Blazevideo HDTV Player Version Detection");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800512";
SCRIPT_DESC = "Blazevideo HDTV Player Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
   exit(0);
}

foreach item(registry_enum_keys(key:key))
{
  appName = registry_get_sz(key:key+item, item:"DisplayName");
  if("BlazeDTV" >< appName)
  {
    bvVer = eregmatch(pattern:"BlazeDTV ([0-9.]+)", string:appName);
    if(bvVer[1] != NULL)
    {
      set_kb_item(name:"Blazevideo/HDTV/Ver", value:bvVer[1]);
      log_message(data:"Blaze Video HDTV version " + bvVer[1] +
                         " was detected on the host");

      ## build cpe and store it as host_detail
      cpe = build_cpe(value:bvVer[1], exp:"^([0-9.]+)", base:"cpe:/a:blazevideo:hdtv_player:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
    exit(0);
  }
}
