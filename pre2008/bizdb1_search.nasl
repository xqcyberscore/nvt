# OpenVAS Vulnerability Test
# $Id: bizdb1_search.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: bizdb1-search.cgi located
#
# Authors:
# RWT roelof@sensepost.com 26/4/2000
#
# Copyright:
# Copyright (C) 2000 Roelof Temmingh <roelof@sensepost.com>
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

tag_summary = "BizDB is a web database integration product
using Perl CGI scripts. One of the scripts,
bizdb-search.cgi, passes a variable's
contents to an unchecked open() call and
can therefore be made to execute commands
at the privilege level of the webserver.

The variable is dbname, and if passed a
semicolon followed by shell commands they
will be executed. This cannot be exploited
from a browser, as the software checks for
a referrer field in the HTTP request. A
valid referrer field can however be created
and sent programmatically or via a network
utility like netcat.

see also : http://www.hack.co.za/daem0n/cgi/cgi/bizdb.htm";
  
# Locate /cgi-bin/bizdb1-search.cgi

if(description)
{
 script_id(10383);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(1104);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
 script_cve_id("CVE-2000-0287");


 name = "bizdb1-search.cgi located";
 script_name(name);


 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2000 Roelof Temmingh <roelof@sensepost.com>");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
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

cgi = string("bizdb1-search.cgi");
res = is_cgi_installed_ka(item:cgi, port:port);
if( res ) {
	if ( is_cgi_installed_ka(item:"openvas" + rand() + ".cgi", port:port) ) exit(0);
	security_message(port);
}
