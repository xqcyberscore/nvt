###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_faslo_player_detect.nasl 7293 2017-09-27 08:49:48Z cfischer $
#
# Faslo Player Version Detection
#
# Authors:
# Maneesh KB <kmaneesh@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_summary = "This script detects the installed version of Faslo player and
  sets the result in KB.";

if(description)
{
  script_id(900253);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 7293 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-27 10:49:48 +0200 (Wed, 27 Sep 2017) $");
  script_tag(name:"creation_date", value:"2009-11-23 07:01:19 +0100 (Mon, 23 Nov 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Faslo Player Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 SecPod");
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

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900253";
SCRIPT_DESC = "Faslo Player Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Faslo")){
  exit(0);
}


fpVer = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion"+
                            "\Uninstall\Faslo", item:"DisplayVersion");
if(fpVer != NULL){
  set_kb_item(name:"FasloPlayer/Ver", value:fpVer);
  log_message(data:"Faslo Player version " + fpVer +
                                              " was detected on the host");
  
  ## build cpe and store it as host_detail
  cpe = build_cpe(value:fpVer, exp:"^([0-9.]+)", base:"cpe:/a:faslo:faslo_player:");
  if(!isnull(cpe))
     register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
}
