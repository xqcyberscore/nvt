# OpenVAS Vulnerability Test
# $Id: smb_nt_ms02-070.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: Flaw in SMB Signing Could Enable Group Policy to be Modified (329170)
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

tag_summary = "The SMB signing capability in the Server Message Block
protocol in Microsoft Windows 2000 and Windows XP allows
attackers to disable the digital signing settings in an
SMB session to force the data to be sent unsigned, then
inject data into the session without detection, e.g. by
modifying group policy information sent from a domain
controller.

Maximum Severity Rating: Moderate

Recommendation: Administrators should install the patch immediately. 

Affected Software: 

Microsoft Windows 2000
Microsoft Windows XP

See
http://www.microsoft.com/technet/security/bulletin/ms02-070.mspx";

if(description)
{
 script_id(11215);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(6367);
 script_cve_id("CVE-2002-1256");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

 name = "Flaw in SMB Signing Could Enable Group Policy to be Modified (329170)";

 script_name(name);
 


 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
 
 script_copyright("This script is Copyright (C) 2003 SECNAP Network Security");
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

if ( hotfix_check_sp(xp:2) == 0 && hotfix_missing(name:"896422") == 0 ) exit(0);

if ( hotfix_check_sp(nt:7, win2k:4, xp:2) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q329170") > 0 )
	security_message(get_kb_item("SMB/transport"));
