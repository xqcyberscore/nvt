# OpenVAS Vulnerability Test
# $Id: uploadskrip.nasl 9348 2018-04-06 07:01:19Z cfischer $
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
 script_oid("1.3.6.1.4.1.25623.1.0.11746");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_cve_id("CVE-2001-0938");
 script_bugtraq_id(3608);
 script_name("AspUpload vulnerability");
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_active");
 script_copyright("This script is Copyright (C) 2003 John Lampe");
 script_family("Web application abuses");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://marc.theaimsgroup.com/?l=bugtraq&m=100715294425985&w=2");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_asp(port:port))exit(0);

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  req = http_get(item:dir + "/Test11.asp", port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if( res == NULL ) continue;

  if ("UploadScript11.asp" >< r) {
    security_message(port);
    exit(0);
  }
}
