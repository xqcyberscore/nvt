###############################################################################
# OpenVAS Vulnerability Test
# $Id: gather_windows_installation_guid.nasl 1.0 2018-10-25 12:06:44Z $
#
# Gather the windows installation guid.
#
# Authors:
# Alex Harwood <alex.harwood@xqcyber.com>
#
# Copyright:
# Copyright (c) 2017 XQ Digital Resilience Limited
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.1.300027");
  script_version("$Revision: 1.0 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-11 16:23:53 +0200 (Tue, 11 Sep 2018) $");
  script_name('Microsoft Windows installation GUID');
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 XQ Cyber");
  script_family("Compliance");
  script_exclude_keys("SMB/samba");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("Compliance/Launch/GSHB", "SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");

OSTYPE = get_kb_item("WMI/WMI_OSTYPE");
OSVER = get_kb_item("SMB/WindowsVersion");

if(!OSVER){
    # We must assume this is not a windows box if we failed to get the windows version.
    exit(0);
}

# Registry key type
type = 'HKLM';
item = 'MachineGuid';
key = "Software\Microsoft\Cryptography";

# Fetch the registry key value
value = registry_get_sz(key:key, item:item, type:type);

if(value == ''){
    exit(0);
}

log_message(data: value);
exit(0);
