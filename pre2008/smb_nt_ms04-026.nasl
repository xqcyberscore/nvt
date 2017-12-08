# OpenVAS Vulnerability Test
# $Id: smb_nt_ms04-026.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: Vulnerability in Exchange Server 5.5 Outlook Web Access XSS (842436)
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
# Tenable adds
# - check for OWA on port 80
# Updated: 2009/04/23 Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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

tag_summary = "The remote host is running a version of the Outlook Web Access which contains 
cross site scripting flaws.

This vulnerability could allow an attacker to convince a user 
to run a malicious script. If this malicious script is run, it would execute 
in the security context of the user. 
Attempts to exploit this vulnerability require user interaction. 

This vulnerability could allow an attacker access to any data on the 
Outlook Web Access server that was accessible to the individual user.

It may also be possible to exploit the vulnerability to manipulate Web browser caches
and intermediate proxy server caches, and put spoofed content in those caches.";

tag_solution = "http://www.microsoft.com/technet/security/bulletin/ms04-026.mspx";

# Ref: Amit Klein (August 2004)

if(description)
{
 script_id(14254);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(10902);
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2004-0203");
 name = "Vulnerability in Exchange Server 5.5 Outlook Web Access XSS (842436)";

 script_name(name);



 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 family = "Windows : Microsoft Bulletins";
 script_family(family);

 script_dependencies("secpod_reg_enum.nasl", "find_service.nasl", "http_version.nasl" );
 script_require_keys("SMB/Registry/Enumerated");
 script_mandatory_keys("SMB/WindowsVersion");
 script_require_ports("Services/www", 80, 139, 445);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("secpod_reg.inc");


# we will first ensure that OWA is running
port = get_http_port(default:80);

if ( ! can_host_asp(port:port) )
        exit(0);

cgi = "/exchange/root.asp";
if(! is_cgi_installed_ka(item:cgi, port:port))
        exit(0);

# display("exchange owa installed\n");

# now check for the patch
if ( hotfix_check_nt_server() <= 0 ) 
	exit(0);

vers = hotfix_check_exchange_installed();
if ( vers == NULL ) 
	exit(0);

if ( hotfix_missing(name:"KB842436") > 0 ) 
	security_message(get_kb_item("SMB/transport"));


