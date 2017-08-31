# OpenVAS Vulnerability Test
# $Id: smb_nt_ms04-001.nasl 6456 2017-06-28 11:19:33Z cfischer $
# Description: Vulnerability in Microsoft ISA Server 2000 H.323 Filter(816458)
#
# Authors:
# Jeff Adams <jadams@netcentrics.com> 
#
# Copyright:
# Copyright (C) 2004 Jeff Adams
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

tag_summary = "A security vulnerability exists in the H.323 filter for Microsoft Internet 
Security and Acceleration Server 2000 that could allow an attacker
to overflow a buffer in the Microsoft Firewall Service in Microsoft Internet 
Security and Acceleration Server 2000.

An attacker who successfully exploited this vulnerability could try to run 
code of their choice in the security context of the Microsoft Firewall Service. 
This would give the attacker complete control over the system. 
The H.323 filter is enabled by default on servers running ISA Server 2000 
computers that are installed in integrated or firewall mode.

Impact of vulnerability: Remote code execution  

Affected Software: 

Microsoft Internet Security and Acceleration Server 2000 Gold, SP1";

tag_solution = "Users using any of the affected
products should install the patch immediately.

Maximum Severity Rating: Critical 

See http://www.microsoft.com/technet/security/bulletin/ms04-001.mspx";


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11992");
  script_version("$Revision: 6456 $");
  script_tag(name:"last_modification", value:"$Date: 2017-06-28 13:19:33 +0200 (Wed, 28 Jun 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(9408);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"IAVA", value:"2004-B-0002");
  script_cve_id("CVE-2003-0819");
  script_name("Vulnerability in Microsoft ISA Server 2000 H.323 Filter(816458)");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 Jeff Adams");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl", "smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

fpc = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc");
if (!fpc) exit(0);

fix = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc/Hotfixes/SP1/291");
if(!fix)security_message(port:0);
