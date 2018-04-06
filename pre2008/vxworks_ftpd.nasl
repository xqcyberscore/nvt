# OpenVAS Vulnerability Test
# $Id: vxworks_ftpd.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: vxworks ftpd buffer overflow
#
# Authors:
# Michael Scheidell at SECNAP
# script derived from aix_ftpd, original script
# written by Renaud Deraison <deraison@cvs.nessus.org>
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

tag_summary = "It might be possible to make the remote FTP server
crash by issuing this command :

	CEL aaaa(...)aaaa
	
This problem is similar to the 'aix ftpd' overflow
but on embedded vxworks based systems like the 3com
nbx IP phone call manager and seems to cause the server
to crash.

*** Note that OpenVAS solely relied on the banner of
*** the remote server to issue this warning.";

tag_solution = "If you are using an embedded vxworks
product, please contact the OEM vendor and reference
WindRiver field patch TSR 296292. If this is the 
3com NBX IP Phone call manager, contact 3com.

This affects VxWorks ftpd versions 5.4 and 5.4.2

For more information, see CERT VU 317417
http://www.kb.cert.org/vuls/id/317417
or full security alert at
http://www.secnap.net/security/nbx001.html";


# Note by rd: 
# 	- Disabled the DoS code, as it will completely crash the
#	  remote host, something that should not be done from within
#	  a ACT_MIXED_ATTACK plugin.

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.11185");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2002-2300");
 script_bugtraq_id(6297);
 name = "vxworks ftpd buffer overflow";
 
 script_name(name);
	     
		 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner"); 
 script_family("FTP");
 
 script_copyright("This script is Copyright (C) 2002 Michael Scheidell");
		  
 script_dependencies("find_service.nasl", "ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 script_require_keys("ftp/vxftpd");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here : 
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;


banner = get_ftp_banner(port: port);

if(!banner)exit(0);
#VxWorks (5.4) FTP server ready
#220 VxWorks (5.4.2) FTP server ready
#above affected,
# below MIGHT be ok:
#220 VxWorks FTP server (VxWorks 5.4.2) ready
# and thus the banner check may be valid

# for some reason, escaping the parens causes a login failure here
#                             (5.4) or (5.4.[1-2])
 if(egrep(pattern:".*xWorks .(5\.4.|5\.4\.[1-2])[^0-9].*FTP",
   	 string:banner)){
  	 security_message(port);
	 } 
