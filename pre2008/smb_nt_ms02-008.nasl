# OpenVAS Vulnerability Test
# $Id: smb_nt_ms02-008.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: XML Core Services patch (Q318203)
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

tag_summary = "XMLHTTP Control Can Allow Access to Local Files.

A flaw exists in how the XMLHTTP control applies IE security zone
settings to a redirected data stream returned in response to a
request for data from a web site. A vulnerability results because
an attacker could seek to exploit this flaw and specify a data
source that is on the user's local system. The attacker could
then use this to return information from the local system to the
attacker's web site. 

Impact of vulnerability: Attacker can read files on client system.

Affected Software: 

Microsoft XML Core Services versions 2.6, 3.0, and 4.0.
An affected version of Microsoft XML Core Services also
ships as part of the following products: 

Microsoft Windows XP 
Microsoft Internet Explorer 6.0 
Microsoft SQL Server 2000 

(note: versions earlier than 2.6 are not affected
files affected include msxml[2-4].dll and are found
in the system32 directory. This might be false
positive if you have earlier version)

See http://www.microsoft.com/technet/security/bulletin/ms02-008.mspx";

if(description)
{
 script_id(10866);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(3699);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_cve_id("CVE-2002-0057");
 name = "XML Core Services patch (Q318203)";
 
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


if ( hotfix_check_sp(nt:7, win2k:5, xp:1) <= 0 ) exit(0);

if ( hotfix_missing(name:"Q832483") > 0 &&
     hotfix_missing(name:"Q318202") > 0 &&
     hotfix_missing(name:"Q318203") > 0 &&
     hotfix_missing(name:"Q317244") > 0 )
	security_message(get_kb_item("SMB/transport"));
