# OpenVAS Vulnerability Test
# $Id: smb_nt_ms02-018.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: Cumulative Patch for Internet Information Services (Q327696)
#
# Authors:
# Michael Scheidell <scheidell at secnap.net>
# Updated: 2009/04/23
# Chandan S <schandan@secpod.com>
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

tag_summary = "Cumulative Patch for Microsoft IIS (Q327696)

Impact of vulnerability: Ten new vulnerabilities, the most
serious of which could enable code of an attacker's choice
to be run on a server.

Recommendation: Users using any of the affected
products should install the patch immediately.

Maximum Severity Rating: Critical 

Affected Software: 

Microsoft Internet Information Server 4.0 
Microsoft Internet Information Services 5.0 
Microsoft Internet Information Services 5.1 

See
http://www.microsoft.com/technet/security/bulletin/ms02-062.mspx

Supersedes

http://www.microsoft.com/technet/security/bulletin/ms02-018.mspx";

if(description)
{
 script_id(10943);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(4006, 4474, 4476, 4478, 4490, 6069, 6070, 6071, 6072);
 script_cve_id("CVE-2002-0147", "CVE-2002-0149",
 	       "CVE-2002-0150", "CVE-2002-0224",
 	       "CVE-2002-0869", "CVE-2002-1182",
	       "CVE-2002-1180", "CVE-2002-1181");
 script_xref(name:"IAVA", value:"2002-A-0002");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 name = "Cumulative Patch for Internet Information Services (Q327696)";
 
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
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}


include("secpod_reg.inc");

if ( hotfix_check_iis_installed() <= 0 ) exit(0);
if ( hotfix_check_sp(nt:7, win2k:3, xp:1 ) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q811114") > 0 &&
     hotfix_missing(name:"Q327696") > 0  ) 
	security_message(get_kb_item("SMB/transport"));
     

