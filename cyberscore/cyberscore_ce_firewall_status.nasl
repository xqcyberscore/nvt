############################################################################### 
# OpenVAS Vulnerability Test
# $Id: cyberscore_ce_firewall_status.nasl 1 2018-06-03 13:55:36 +0100 (Sun, 03 Jun 2018) mattb $
#
# Description:
# Retrieves the state of the onhost firewall
#
# Authors:
# Matt Blades <matthew.blades@xqcyber.com>
#
# Copyright:
# Copyright (c) 2018 XQ Cyber, https://www.xqcyber.com
#
# Checks the registry to determine the values of the 
# HKLM\Software\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy
# - StandardProfile
# - DomainProfile
# - PublicProfile
#
# keys, and retrieves the values:
#
# 00 - disabled for that profile
# 01 - enabled for that profile
#
# This plugin should return one or more lines:
# <domain | standard | public>:<value | undefined | err_no_key>
#
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
  script_oid("1.3.6.1.4.1.25623.1.1.300006");
  script_version("$Revision: 1 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-03 13:55:15 +0100 (Sun, 03 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-06-01 15:41:15 +0100 (Fri, 01 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Cyber Essentials Plus - Control 1.6: Confirm local firewall status");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 XQ Cyber");
  script_family("Compliance");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"Cyber Essentials Plus - Control 1.6: Confirm local firewall status");
  script_tag(name:"qod_type", value:"registry");
 
  script_dependencies("secpod_reg_enum.nasl", "smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
 
  exit(0);
}
 
include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");
 
## Variable Initialization
key = "SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\";

domainKey = key + "DomainProfile";
domainValue = "";

standardKey = key + "StandardProfile";
standardValue = "";

publicKey = key + "PublicProfile";
publicValue = "";

item = "EnableFirewall";
report = "";

# Ensure the registry keys exist for domain profile, and then fetch
if (registry_key_exists (key:domainKey, type:"HKLM")) {
	domainValue = registry_get_dword(key:domainKey, item:item, type:"HKLM");
	report = report + "domain:" + int(domainValue) + "\n";

} else {
	report = report + "domain:err_no_key - " + domainKey + "\n";
}

# Ensure the registry keys exist for standard profile, and then fetch
if (registry_key_exists (key:standardKey, type:"HKLM")) {
	standardValue = registry_get_dword(key:standardKey, item:item, type:"HKLM");
	report = report + "standard:" + int(standardValue) + "\n";

} else {
	report = report + "standard:err_no_key - " + standardKey + "\n";
}

# Ensure the registry keys exist for public profile, and then fetch
if (registry_key_exists (key:publicKey, type:"HKLM")) {
	publicValue = registry_get_dword(key:publicKey, item:item, type:"HKLM");
	report = report + "public:" + int(publicValue) + "\n";

} else {
	report = report + "public:err_no_key - " + publicKey + "\n";
}

# Return the findings 
log_message (data:report);
 