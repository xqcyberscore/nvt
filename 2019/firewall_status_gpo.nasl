##############################################################################
# OpenVAS Vulnerability Test
# $Id: firewall_status_gpo.nasl 11344 2018-09-12 06:57:52Z emoss $
#
# Retrieves the state of the onhost firewall which has been set by domain policy
#
# Authors:
# Matt Blades <matthew.blades@xqcyber.com>
# Stephen Penn <stephen.penn@xqcyber.com>
#
# Copyright (c) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.1.300038");
  script_version("$Revision: 11344 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-12 08:57:52 +0200 (Wed, 12 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-08-16 14:08:29 +0200 (Thu, 16 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name("Microsoft Windows Firewall: Inbound connections (GPO): 'EnableFirewall'");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_family("Compliance");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name:"summary", value:"This test checks if the Windows firewall is enabled for each profile");

  exit(0);
}

include("smb_nt.inc");

key = 'SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\';

domainKey = key + "DomainProfile";
domainValue = 'null';

privateKey = key + "PrivateProfile";
privateValue = 'null';

publicKey = key + "PublicProfile";
publicValue = 'null';

item = "EnableFirewall";
report = "";

# Fetch domain key
regDomainValue = registry_get_dword(key:domainKey, item:item, type:"HKLM");
if(regDomainValue != "" && !isnull(regDomainValue)) {
	domainValue = regDomainValue;
}
report +=  "domain: " + domainValue + "\n";

# Fetch private key
regPrivateValue = registry_get_dword(key:privateKey, item:item, type:"HKLM");
if(regPrivateValue != "" && !isnull(regPrivateValue)) {
	privateValue = regPrivateValue;
}
report += "private: " + privateValue + "\n";

# Fetch public key
regPublicValue = registry_get_dword(key:publicKey, item:item, type:"HKLM");
if(regPublicValue != "" && !isnull(regPublicValue)) {
	publicValue = regPublicValue;
}
report += "public: " + publicValue;

# Return the findings
log_message(data:report);
