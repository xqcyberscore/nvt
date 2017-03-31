# OpenVAS Vulnerability Test
# $Id: uploadskrip.nasl 3359 2016-05-19 13:40:42Z antu123 $
# Description: AspUpload vulnerability
#
# Authors:
# John Lampe <j_lampe@bellsouth.net>
#
# Copyright:
# Copyright (C) 2003 John Lampe
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

tag_summary = "The remote web server contains an ASP script that may allow uploading
of arbitrary files. 

Description :

At least one example script distributed with AspUpload appears to be
installed on the remote web server.  AspUpload is an ASP script that
supports saving and processing files uploading through other web
scripts, and the example script likely contains a flaw that allows an
attacker to upload arbitrary files and store them anywhere on the
affected drive.";

tag_solution = "Unknown at this time.";

if(description)
{
 script_id(11746);
 script_version("$Revision: 3359 $");
 script_tag(name:"last_modification", value:"$Date: 2016-05-19 15:40:42 +0200 (Thu, 19 May 2016) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_cve_id("CVE-2001-0938");
 script_bugtraq_id(3608);
 
 name = "AspUpload vulnerability";
 script_name(name);
 

 summary = "Checks for the AspUpload software";
 
 script_summary(summary);
 
 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_active");
 
 
 script_copyright("This script is Copyright (C) 2003 John Lampe");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://marc.theaimsgroup.com/?l=bugtraq&m=100715294425985&w=2");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_asp(port:port))exit(0);

 
foreach dir (cgi_dirs())
{
	req = http_get(item:dir + "/Test11.asp", port:port);
	res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
	if( res == NULL ) exit(0);
	if ("UploadScript11.asp" >< r) 
		{
			security_message(port);
			exit(0);
		}
}
