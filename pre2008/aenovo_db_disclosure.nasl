# OpenVAS Vulnerability Test
# $Id: aenovo_db_disclosure.nasl 6056 2017-05-02 09:02:50Z teissa $
# Description: aeNovo Database Content Disclosure Vulnerability
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

# aeNovo Database Content Disclosure Vulnerability
# From: farhad koosha <farhadkey@yahoo.com>
# Date: 2005-03-12 19:59

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.17323");
 script_version("$Revision: 6056 $");
 script_tag(name:"last_modification", value:"$Date: 2017-05-02 11:02:50 +0200 (Tue, 02 May 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_bugtraq_id(12678);
 script_name("aeNovo Database Content Disclosure Vulnerability");
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2005 Noam Rathaus");
 script_family("Web application abuses");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 script_tag(name : "solution" , value : "Restrict access the the aeNovo's database file or directory by setting
 file/directory restrictions.");
 script_tag(name : "summary" , value : "aeNovo is a web content management system. Due to improper file permission
 settings on the database directory it is possible for a remote attacker
 to download the product's database file and grab from it sensitive information.");

 script_tag(name:"solution_type", value:"Workaround");
 script_tag(name:"qod_type", value:"remote_app");
 exit(0);
}

#
# The script code starts here
#

debug = 0;

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

function check(loc)
{

 if(loc == "/") loc = "";

 if (debug) { display("loc: ", loc, "\n"); }
 req = http_get(item:string(loc, "/aeNovo1.mdb"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if( r == NULL )exit(0);

 if (debug) { display("r: [", r, "]\n"); }
 if (("Content-Type: application/x-msaccess" >< r) && ('Standard Jet DB' >< r))
 {
  security_message(port:port);
  exit(0);
 }
}

foreach dir (make_list_unique("/dbase", "/mdb-database", cgi_dirs(port:port)))
{
 check(loc:dir);
}

exit(99);