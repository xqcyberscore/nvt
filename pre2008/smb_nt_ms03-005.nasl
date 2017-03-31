# OpenVAS Vulnerability Test
# $Id: smb_nt_ms03-005.nasl 5371 2017-02-20 15:52:15Z cfi $
# Description: Unchecked Buffer in XP Redirector (Q810577)
#
# Authors:
# Michael Scheidell SECNAP Network Security
#
# Copyright:
# Copyright (C) 2003 SECNAP Network Security
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

tag_summary = "The remote host is vulnerable to a flaw in the RPC redirector
which can allow a local attacker to run code of its choice
with the SYSTEM privileges.";

tag_solution = "see http://www.microsoft.com/technet/security/bulletin/ms03-005.mspx";

if(description)
{
 script_id(11231);
 script_version("$Revision: 5371 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-20 16:52:15 +0100 (Mon, 20 Feb 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(6778);
 script_cve_id("CVE-2003-0004");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

 name = "Unchecked Buffer in XP Redirector (Q810577)";

 script_name(name);
 

 summary = "Checks for MS Hotfix Q810577";

 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
 
 script_copyright("This script is Copyright (C) 2003 SECNAP Network Security");
 family = "Windows : Microsoft Bulletins";
 script_family(family);
 
 script_dependencies("secpod_reg_enum.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_mandatory_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("secpod_reg.inc");

if ( hotfix_check_sp(xp:2) <= 0 ) exit(0);
if ( hotfix_missing(name:"810577") > 0 &&
     hotfix_missing(name:"885835") > 0  )
	security_message(get_kb_item("SMB/transport"));
