##############################################################################
# OpenVAS Vulnerability Test
# $Id: win_autoconnect_allowed_oem.nasl 10305 2018-06-22 13:48:30Z emoss $
#
# Check value for Allow Windows to automatically connect to suggested open 
# hotspots, to networks shared by contacts, and to hotspots offering paid services
#
# Authors:
# Emanuel Moss <emanuel.moss@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.109339");
  script_version("$Revision: 10305 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-22 15:48:30 +0200 (Fri, 22 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-06-22 14:49:11 +0200 (Fri, 22 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name('Microsoft Windows 10: Automatically connect to suggested open hotspots');
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("smb_reg_service_pack.nasl", "os_detection.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_tag(name: "summary", value: "This test checks the setting for policy 
'Allow Windows to automatically connect to suggested open hotspots, to networks 
shared by contacts, and to hotspots offering paid services' on Windows hosts (at 
least Windows 10).

The policy setting determines whether users can enable the following WLAN 
settings: 'Connect to suggested open hotspots,' 'Connect to networks shared by 
my contacts,' and 'Enable paid services'.");
  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  policy_logging(text:'Host is no Microsoft Windows System or it is not possible
to query the registry.');
  exit(0);
}

HostDetails = get_kb_list("HostDetails");
if("cpe:/o:microsoft:windows_10" >!< HostDetails){
  policy_logging(text:'Host is not a Microsoft Windows 10 system. 
This setting applies to Windows 10 systems only.');
  exit(0);
}

title = 'Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services';
fixtext = 'Set following UI path accordingly:
Computer Configuration/Administrative Templates/Network/WLAN Service/WLAN Settings/' + title;
type = 'HKLM';
key = 'Software\\Microsoft\\wcmsvc\\wifinetworkmanager\\config';
item = 'AutoConnectAllowedOEM';

value = registry_get_dword(key:key, item:item, type:type);
if(!value){
  value = 'none';
}

policy_logging_registry(type:type,key:key,item:item,value:value);
policy_set_kb(val:value);
policy_fixtext(fixtext:fixtext);
policy_control_name(title:title);

exit(0);