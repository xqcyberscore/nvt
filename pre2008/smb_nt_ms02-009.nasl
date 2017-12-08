# OpenVAS Vulnerability Test
# $Id: smb_nt_ms02-009.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: IE VBScript Handling patch (Q318089)
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

tag_summary = "Incorrect VBScript Handling in IE can Allow Web 
Pages to Read Local Files.

Impact of vulnerability: Information Disclosure

Affected Software: 

Microsoft Internet Explorer 5.01
Microsoft Internet Explorer 5.5 
Microsoft Internet Explorer 6.0 

See
http://www.microsoft.com/technet/security/bulletin/ms02-009.mspx
and: Microsoft Article
Q319847 MS02-009 May Cause Incompatibility Problems Between
 VBScript and Third-Party Applications";

if(description)
{
 script_id(10926);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(4158);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_cve_id("CVE-2002-0052");
 name = "IE VBScript Handling patch (Q318089)";
 
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
 script_exclude_keys("SMB/WinXP/ServicePack");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

port = get_kb_item("SMB/transport");
if(!port) port = 139;

key = get_kb_item ("SMB/Registry/HKLM/SOFTWARE/Microsoft/Active Setup/Installed Components/{4f645220-306d-11d2-995d-00c04f98bbc9}/Version");
if (!key) exit (0);


if(ereg(pattern:"^([1-4],.*|5,([0-5],.*|6,0,([0-9]?[0-9]?[0-9]$|[0-6][0-9][0-9][0-9]|7([0-3]|4([01]|2[0-5])))))", string:key))
{ 
  security_message(port);
  exit(0);
}
