# OpenVAS Vulnerability Test
# $Id: smb_nt_ms03-041.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: Vulnerability in Authenticode Verification Could Allow Remote Code Execution (823182)
#
# Authors:
# Jeff Adams <jeffrey.adams@hqda.army.mil>
#
# Copyright:
# Copyright (C) 2003 Jeff Adams
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

tag_summary = "There is a vulnerability in Authenticode that, under certain low memory 
conditions, could allow an ActiveX control to download and install without 
presenting the user with an approval dialog. To exploit this vulnerability, 
an attacker could host a malicious Web Site designed to exploit this 
vulnerability. If an attacker then persuaded a user to visit that site an 
ActiveX control could be installed and executed on the user's system. 
Alternatively, an attacker could create a specially formed HTML e-mail and
send it to the user. 

Exploiting the vulnerability would grant the attacker with the same privileges 
as the user.";

tag_solution = "see http://www.microsoft.com/technet/security/bulletin/ms03-041.mspx";

if(description)
{
 script_id(11886);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(8830);
 script_xref(name:"IAVA", value:"2003-B-0006");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2003-0660");
 
 name = "Vulnerability in Authenticode Verification Could Allow Remote Code Execution (823182)";
 
 script_name(name);
 


 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
 
 script_copyright("This script is Copyright (C) 2003 Jeff Adams");
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

if ( hotfix_check_sp(win2k:5, xp:2, win2003:1) <= 0 ) exit(0);
if ( hotfix_missing(name:"KB823182") > 0 )
	security_message(get_kb_item("SMB/transport"));

