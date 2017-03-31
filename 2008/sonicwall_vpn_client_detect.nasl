# OpenVAS Vulnerability Test
# $Id: sonicwall_vpn_client_detect.nasl 5370 2017-02-20 15:24:26Z cfi $
# Description: SonicWall Global VPN Client Detection
#
# Authors:
# Ferdy Riphagen 
# Modified by Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2008 David Maciejak
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
#

tag_summary = "This script detects the installed version of
SonicWall Global VPN Client and sets the result in KB.";

if (description) {
 script_id(80044);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 5370 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-20 16:24:26 +0100 (Mon, 20 Feb 2017) $");
 script_tag(name:"creation_date", value:"2008-10-24 20:38:19 +0200 (Fri, 24 Oct 2008)");
 script_tag(name:"cvss_base", value:"0.0");

 desc = "
 Summary:
 " + tag_summary;
 name = "SonicWall Global VPN Client Detection";
 script_name(name);
 summary = "Detects the presence and version of the SNWL Global VPN Client";
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2008 Ferdy Riphagen");

 script_require_ports(139, 445);
 script_dependencies("secpod_reg_enum.nasl");
 script_require_keys("SMB/login", "SMB/password", "SMB/name", "SMB/transport");
 script_mandatory_keys("SMB/WindowsVersion");

 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.80044";
SCRIPT_DESC = "SonicWall Global VPN Client Detection";

if(!get_kb_item("SMB/WindowsVersion")){
   exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\SWGVpnClient.exe";

if(!registry_key_exists(key:key)){
    exit(0);
}

path = registry_get_sz(key:key, item:"Path");

if(path) {

  file = path + "\SWGVpnClient.exe";
  version = GetVersionFromFile(file:file,verstr:"prod");
  if(!isnull(version)){
    set_kb_item(name:"SMB/SonicWallGlobalVPNClient/Version", value:version);
    set_kb_item(name:"SMB/SonicWallGlobalVPNClient/Path", value:path);

    ## build cpe and store it as host_detail
    cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:sonicwall:global_vpn_client:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    exit(0);
  }  
}  

exit(0);
