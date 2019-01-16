############################################################################### 
# OpenVAS Vulnerability Test
# $Id: cyberscore_ce_full_disk_encryption_check.nasl 1 2018-06-04 18:35:57 +0100 (Mon, 04 Jun 2018) mattb $
#
# Description:
# Checks the FDE status of drives found on the system
#
# Authors:
# Matt Blades <matthew.blades@xqcyber.com>
#
# Copyright:
# Copyright (c) 2018 XQ Cyber, https://www.xqcyber.com
#
# Detailed description:
# Queries WMI to retrieve the FDE status of any fixed disks present within
# the system.
#
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
  script_oid("1.3.6.1.4.1.25623.1.1.300007");
  script_version("$Revision: 1 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-05 18:35:57 +0100 (Mon, 04 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-06-03 14:21:57 +0100 (Sun, 03 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Cyber Essentials Plus - Control 1.7: Confirm disk encryption status");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 XQ Cyber");
  script_family("Compliance");
  script_dependencies("gb_wmi_access.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("WMI/access_successful");
  script_tag(name:"summary", value:"Cyber Essentials Plus - Control 1.7: Confirm disk encryption status");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");

host = get_host_ip();
username = kb_smb_login(); 
domain = kb_smb_domain();

if (domain) {
  username = domain + "/" + username;
}
password  = kb_smb_password();

# As this query is being passed to a command-line tool, it needs to be escaped
query = "SELECT DriveLetter,ProtectionStatus,VolumeType FROM win32_encryptablevolume WHERE VolumeType=0 OR VolumeType=1";
namespace = "root/cimv2/security/microsoftvolumeencryption";

# Assemble the command
i = 0;
argv[i++] = "impacket.sh";
argv[i++] = query;
argv[i++] = namespace;
argv[i++] = username +":"+ password +"@"+ host;

# Run the constructed command
res = pread( cmd:"impacket.sh", argv:argv);

if (!res) {
  output = "Could not run query";
} else {
  output = res;
}

log_message (data:output);
