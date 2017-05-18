# OpenVAS Vulnerability Test
# $Id: wu_ftpd_skey_remote_buff.nasl 6053 2017-05-01 09:02:51Z teissa $
# Description: wu-ftpd S/KEY authentication overflow
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

tag_summary = "The remote Wu-FTPd server seems to be vulnerable to a remote overflow.

This version contains a remote overflow if s/key support is enabled. 
The skey_challenge function fails to perform bounds checking on the 
name variable resulting in a buffer overflow. 
With a specially crafted request, an attacker can execute arbitrary 
code resulting in a loss of integrity and/or availability.

It appears that this vulnerability may be exploited prior to authentication.
It is reported that S/Key support is not enabled by default, 
though some operating system distributions which ship Wu-Ftpd may have it 
enabled.

*** OpenVAS solely relied on the banner of the remote server
*** to issue this warning, so it may be a false positive.";

tag_solution = "Upgrade to Wu-FTPd 2.6.3 when available or disable SKEY or apply the
patches available at http://www.wu-ftpd.org";

# Ref: Michal Zalewski & Michael Hendrickx

if(description)
{
 script_id(14372);
 script_version("$Revision: 6053 $");
 script_tag(name:"last_modification", value:"$Date: 2017-05-01 11:02:51 +0200 (Mon, 01 May 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(8893);
 script_cve_id("CVE-2004-0185");
 
 script_xref(name:"OSVDB", value:"2715");
 script_xref(name:"RHSA", value:"RHSA-2004:096-09");
 script_xref(name:"DSA", value:"DSA-457-1");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

 
 name = "wu-ftpd S/KEY authentication overflow ";
 
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

port = get_kb_item("Services/ftp");
if(!port)
	port = 21;
if (! get_port_state(port)) 
	exit(0);

banner = get_ftp_banner(port: port);
if( banner == NULL ) 
	exit(0);

if(egrep(pattern:".*wu-(2\.(5\.|6\.[012])).*", string:banner))
	security_message(port);
