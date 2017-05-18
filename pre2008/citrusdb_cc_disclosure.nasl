# OpenVAS Vulnerability Test
# $Id: citrusdb_cc_disclosure.nasl 6046 2017-04-28 09:02:54Z teissa $
# Description: Credit Card Data Disclosure in CitrusDB
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

# Maximillian Dornseif <dornseif@informatik.rwth-aachen.de>
# 2005-02-13 00:31
# Credit Card data disclosure in CitrusDB

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.16388");
 script_version("$Revision: 6046 $");
 script_tag(name:"last_modification", value:"$Date: 2017-04-28 11:02:54 +0200 (Fri, 28 Apr 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(12402);
 script_cve_id("CVE-2005-0229");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_name("Credit Card Data Disclosure in CitrusDB");
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2005 Noam Rathaus");
 script_family("Web application abuses");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 script_tag(name : "solution" , value : "Update to CitrusDB version 0.3.6 or higher and set the
 option '$path_to_ccfile' in the configuration to a path not 
 accessible via HTTP.");
 script_tag(name : "summary" , value : "The remote host is running CitrusDB, an open-source customer database
 application written in PHP.

 CitrusDB uses a textfile to temporarily store credit card information.
 This textfile is located in the web tree via a static URL and thus
 accessible to third parties. It also isn't deleted after processing
 resulting in a big window of opportunity for an attacker.

 Workaround : Either deny access to the file using access restriction 
 features of the remote webserver or change CitrusDB to use a file 
 outside the document root and not accessible via HTTP.");

 script_tag(name:"solution_type", value:"VendorFix");
 script_tag(name:"qod_type", value:"remote_app");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

function check(loc)
{

 if(loc == "/") loc = "";

 req = http_get(item:string(loc, "/newfile.txt"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if( r == NULL )exit(0);

 if ('"CHARGE","' >< r)
 {
  security_message(port:port);
  exit(0);
 }
}

foreach dir (make_list_unique("/io", cgi_dirs(port:port)))
{
 check(loc:dir);
}

exit(99);