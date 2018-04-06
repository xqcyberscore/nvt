# OpenVAS Vulnerability Test
# $Id: photopost_sql_injection.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: PhotoPost showgallery.php SQL Injection
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2005 Noam Rathaus
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

tag_summary = "The remote version of PhotoPost PHP contains a vulnerability in the file
'showgallery.php' which allows a remote attacker to cause the program to
execute arbitrary SQL statements against the remote database.";

tag_solution = "Upgrade to the newest version of this software.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.16101");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_cve_id("CVE-2005-0273", "CVE-2005-0274");
 script_bugtraq_id(12156, 12157);
 script_xref(name:"OSVDB", value:"12741");
 script_xref(name:"OSVDB", value:"12742");
 name = "PhotoPost showgallery.php SQL Injection";
 script_name(name);
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 
 script_copyright("This script is Copyright (C) 2005 Noam Rathaus");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("photopost_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.gulftech.org/?node=research&article_id=00063-01032005");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/photopost"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 loc = matches[2];
 req = http_get(item:string(loc, "/showgallery.php?cat=1'"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if(r && "SELECT id,catname,description,photos" >< r) 
 	security_message(port);
}
