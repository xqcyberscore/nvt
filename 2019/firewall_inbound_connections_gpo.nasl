###############################################################################
# OpenVAS Vulnerability Test
# $Id: firewall_inbound_connections_gpo.nasl 1 2019-03-22 13:55:36 +0100 (Sun, 03 Jun 2018) mattb $
#
# Description:
# Retrieves the default behaviour of firewall with inbound connections which was set by domain policy
#
# Authors:
# Matt Blades <matthew.blades@xqcyber.com>
# Stephen Penn <stephen.penn@xqcyber.com>
#
# Copyright (c) 2019 XQ Cyber, https://www.xqcyber.com
#
# Checks the registry to determine the values of the
# SOFTWARE\Policies\Microsoft\WindowsFirewall\
# - PrivateProfile
# - DomainProfile
# - PublicProfile
#
# keys, and retrieves the values:
#
# 00 - disabled for that profile
# 01 - enabled for that profile
#
# This plugin should return one or more lines:
# <domain | standard | public>: <value | null>
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
  script_oid("1.3.6.1.4.1.25623.1.1.300039");
  script_version("$Revision: 1 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-22 13:55:15 +0100 (Sun, 03 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-06-01 15:41:15 +0100 (Fri, 01 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Cyber Essentials Plus - Control 1.6: Confirm firewall status (GPO): 'DefaultInboundAction'");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2019 XQ Cyber");
  script_family("Compliance");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"Cyber Essentials Plus - Control 1.6: Confirm firewall status (GPO): 'DefaultInboundAction'");
  script_tag(name:"qod_type", value:"registry");

  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");

  exit(0);
}

include("smb_nt.inc");

## Variable Initialization
key = 'SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\';

domainKey = key + "DomainProfile";
domainValue = "null";

privateKey = key + "PrivateProfile";
privateValue = "null";

publicKey = key + "PublicProfile";
publicValue = "null";

item = "DefaultInboundAction";
report = "";

# Fetch domain value
regDomainValue = registry_get_dword(key:domainKey, item:item, type:"HKLM");
if(regDomainValue != "") {
	domainValue = regDomainValue;
}
report += "domain: " + domainValue + "\n";


# Fetch private value
regPrivateValue = registry_get_dword(key:privateKey, item:item, type:"HKLM");
if(regPrivateValue != "") {
	privateValue = regPrivateValue;
}
report += "private: " + privateValue + "\n";

# Fetch public value
regPublicValue = registry_get_dword(key:publicKey, item:item, type:"HKLM");
if(regPublicValue != "") {
	publicValue = regPublicValue;
}
report += "public: " + publicValue;

# Return the findings
log_message(data:report);
