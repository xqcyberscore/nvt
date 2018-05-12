##############################################################################
# OpenVAS Vulnerability Test
# $Id: win10_prevent_users_installing_printer_drivers.nasl 9774 2018-05-09 10:20:10Z emoss $
#
# Check value for Devices: Prevent users from installing printer drivers
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
  script_oid("1.3.6.1.4.1.25623.1.0.109160");
  script_version("$Revision: 9774 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-09 12:20:10 +0200 (Wed, 09 May 2018) $");
  script_tag(name:"creation_date", value:"2018-05-07 16:00:32 +0200 (Mon, 07 May 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name('Microsoft Windows 10: Devices: Prevent users from installing printer drivers');
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_tag(name: "summary", value: "For a device to print to a network printer, 
the driver for that network printer must be installed locally. 
The Devices: Prevent users from installing printer drivers policy setting 
determines who can install a printer driver as part of adding a network printer. 
When you set the value to Enabled, only Administrators and Power Users can 
install a printer driver as part of adding a network printer. Setting the value 
to Disabled allows any user to install a printer driver as part of adding a 
network printer. This setting prevents unprivileged users from downloading and 
installing an untrusted printer driver.");  
  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  policy_logging(text:'Host is no Microsoft Windows System or it is not possible
to query the registry.');
  exit(0);
}

WindowsName = get_kb_item("SMB/WindowsName");
if('windows 10' >!< tolower(WindowsName)){
  policy_logging(text:'Host is not a Microsoft Windows 10 System.');
  exit(0); 
}

type = 'HKLM';
key = 'SYSTEM\\CurrentControlSet\\Control\\Print\\Providers\\LanMan Print Services\\Servers';
item = 'AddPrinterDrivers';
value = registry_get_dword(key:key, item:item, type:type);
if( value == ''){
  value = 'none';
}
policy_logging_registry(type:type,key:key,item:item,value:value);
policy_set_kb(val:value);

exit(0);