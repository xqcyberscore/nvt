# OpenVAS Vulnerability Test
# $Id: wu_ftpd_mail_admin.nasl 6063 2017-05-03 09:03:05Z teissa $
# Description: wu-ftpd MAIL_ADMIN overflow
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
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

tag_summary = "The remote Wu-FTPd server seems to be vulnerable to a remote flaw.

This version fails to properly check bounds on a pathname when Wu-Ftpd is 
compiled with MAIL_ADMIN enabled resulting in a buffer overflow. With a 
specially crafted request, an attacker can possibly execute arbitrary code 
as the user Wu-Ftpd runs as (usually root) resulting in a loss of integrity, 
and/or availability.

It should be noted that this vulnerability is not present within the default 
installation of Wu-Ftpd. 

The server must be configured using the 'MAIL_ADMIN' option to notify an 
administrator when a file has been uploaded.

*** OpenVAS solely relied on the banner of the remote server
*** to issue this warning, so it may be a false positive.";

tag_solution = "Upgrade to Wu-FTPd 2.6.3 when available";

# Ref: Adam Zabrocki <pi3ki31ny@wp.pl>

if(description)
{
 script_id(14371);
 script_version("$Revision: 6063 $");
 script_tag(name:"last_modification", value:"$Date: 2017-05-03 11:03:05 +0200 (Wed, 03 May 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2003-1327");
 script_bugtraq_id(8668);
 script_xref(name:"OSVDB", value:"2594");

 
 name = "wu-ftpd MAIL_ADMIN overflow";
 
 script_name(name);
	     

		    
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 script_family("FTP");
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
		  
 script_dependencies("find_service.nasl", "ftpserver_detect_type_nd_version.nasl", "secpod_ftp_anonymous.nasl");
 script_require_keys("ftp/login", "ftp/wuftpd");
 script_require_ports("Services/ftp", 21);
  
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here : 
#
include("ftp_func.inc");

#login = get_kb_item("ftp/login");
#pass  = get_kb_item("ftp/password");

port = get_kb_item("Services/ftp");
if(!port)
	port = 21;
if (! get_port_state(port)) 
	exit(0);

banner = get_ftp_banner(port: port);
if( banner == NULL ) 
	exit(0);

if(egrep(pattern:".*wu-2\.6\.[012].*", string:banner))
	security_message(port);

