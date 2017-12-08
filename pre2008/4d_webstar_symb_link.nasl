# OpenVAS Vulnerability Test
# $Id: 4d_webstar_symb_link.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: 4D WebStar Symbolic Link Vulnerability
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

tag_summary = "The remote server is running 4D WebStar FTP Server.

4D WebStar is reportedly vulnerable to a local symbolic link vulnerability.
This issue is due to a design error that causes the application
to open files without properly verifying their existence or their absolute location.

Successful exploitation of this issue will allow an attacker to write 
to arbitrary files writable by the affected application, 
facilitating privilege escalation.";

tag_solution = "Upgrade to 4D WebStar 5.3.3 or later.";

#  Ref: @stake inc.

if(description)
{
 script_id(14241);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2004-0698");
 script_bugtraq_id(10714);
 script_tag(name:"cvss_base", value:"3.6");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:N");
 
 name = "4D WebStar Symbolic Link Vulnerability";
 script_name(name);
 

 
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 
 family = "Remote file access";
 script_family(family);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80, "Services/ftp", 21);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.atstake.com/research/advisories/2004/a071304-1.txt");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("ftp_func.inc");


# 4D runs both FTP and WWW on the same port
port = get_http_port(default:80);
if(!get_port_state(port))
	exit(0);

banner = get_http_banner(port:port);
if ( ! banner ) 
	exit(0);
# Server: 4D_WebSTAR_S/5.3.3 (MacOS X)
if ( "4D_WebSTAR" >< banner &&
     egrep(pattern:"^Server: 4D_WebSTAR.*/([0-4]\.|5\.([0-2]\.|3\.[0-2][^0-9]))", string:banner) ) 
{
 port = get_kb_item("Services/ftp");
 if ( ! port ) 
	port = 21;
 if ( ! get_port_state(port) ) 
	exit(0);
 ftpbanner = get_ftp_banner(port:port);
 if ( egrep(string:ftpbanner, pattern:"^220 FTP server ready\."))
 { 
  security_message(port);
 }
}
