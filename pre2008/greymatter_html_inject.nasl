# OpenVAS Vulnerability Test
# $Id: greymatter_html_inject.nasl 3362 2016-05-20 11:19:10Z antu123 $
# Description: Greymatter gm.cgi HTML injection flaw
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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

tag_summary = "The remote host is using Greymatter, an opensource weblogging and 
journal software written in perl.

A vulnerability exists in this version which may allow 
an attacker to execute arbitrary HTML and script code in
the context of the user's browser.";

tag_solution = "Upgrade to the latest version of this software";

#  Ref: poizon@securityinfo.ru

if(description)
{
 script_id(19752);
 script_version("$Revision: 3362 $");
 script_tag(name:"last_modification", value:"$Date: 2016-05-20 13:19:10 +0200 (Fri, 20 May 2016) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_cve_id("CVE-2005-2816");
 script_bugtraq_id(14703);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 
 name = "Greymatter gm.cgi HTML injection flaw";

 script_name(name);
 

 summary = "Checks the version of the remote Greymatter";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 
 script_copyright("This script is Copyright (C) 2005 David Maciejak");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);

if ( !get_port_state(port))exit(0);

function check(loc)
{
 req = http_get(item:string(loc, "/gm.cgi"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if (egrep(pattern:'<META NAME="Generator" CONTENT="Greymatter (0\\.|1\\.([0-2][0-9]*[a-z]?|3|3\\.[01]))">', string:r)  )
 {
   security_message(port);
   exit(0);
 }
}

dirs = make_list("/greymatter", cgi_dirs());

foreach dir (dirs)
{
 check(loc:dir);
}

