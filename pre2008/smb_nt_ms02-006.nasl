# OpenVAS Vulnerability Test
# $Id: smb_nt_ms02-006.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Checks for MS HOTFIX for snmp buffer overruns
#
# Authors:
# Michael Scheidell <scheidell at secnap.net>
#
# Copyright:
# Copyright (C) 2002 Michael Scheidell
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

tag_summary = "There is an Unchecked Buffer in SNMP Service and this
checks to see if the Microsoft Patch has been applied
(only checks NT/Win2k and XP PRo).

Impact of vulnerability: Run code of attacker's choice
and denial of service attacks.

Also may run snmp detect to see if snmp is running on
this host.";

tag_solution = "http://www.microsoft.com/technet/security/bulletin/ms02-006.mspx";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.10865");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2002-0053");
 name = "Checks for MS HOTFIX for snmp buffer overruns";
 
 script_name(name);
 
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
 
 script_copyright("This script is Copyright (C) 2002 Michael Scheidell");
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

if ( hotfix_check_sp(nt:7, win2k:3, xp:1) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q314147") > 0 )
	security_message(get_kb_item("SMB/transport"));

