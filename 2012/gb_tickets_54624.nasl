###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tickets_54624.nasl 3062 2016-04-14 11:03:39Z benallard $
#
# Tickets CAD Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

tag_summary = "Tickets CAD is prone to multiple vulnerabilities.

1. A Reflective XSS vulnerability exist in the search function, search.php within the application.
2. A Stored XSS vulnerability exist in log.php while creating a new log entry.
3. Information disclosure exist which allows users even the guest account to view the tables of the sql database.

Tickets CAD 2.20G is vulnerable; other versions may also be affected.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103530";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(54803);
 script_version ("$Revision: 3062 $");
 script_tag(name:"cvss_base", value:"3.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:N");
 script_name("Tickets CAD Multiple Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/20268/");
 script_xref(name : "URL" , value : "http://www.ticketscad.org");

 script_tag(name:"last_modification", value:"$Date: 2016-04-14 13:03:39 +0200 (Thu, 14 Apr 2016) $");
 script_tag(name:"creation_date", value:"2012-08-06 12:26:58 +0200 (Mon, 06 Aug 2012)");
 script_summary("Determine if it is possible to vies the users table");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(!can_host_php(port:port))exit(0);

dirs = make_list("/tickets",cgi_dirs());

foreach dir (dirs) {

  url = dir + '/main.php';

  if(buf = http_vuln_check(url:url, pattern:"Welcome to Tickets",port:port,check_header:TRUE)) {

    co = eregmatch(pattern:"Set-Cookie: ([^;]+)", string:buf);
    if(isnull(co[1]))exit(0);

    c = co[1];
    host = get_host_name();

    ex = 'frm_user=guest&frm_passwd=guest&frm_daynight=Day&frm_referer=http%3A%2F%2F' + host  + '%2FDAC213%2Ftop.php';
    len = strlen(ex);

    req = string("POST ", url, " HTTP/1.1\r\n",
                 "Host: ", host,"\r\n",
                 "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
                 "Cookie: ", c,"\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ",len,"\r\n",
                 "\r\n",
                 ex);

    result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

    if(result =~ "HTTP/1.. 302" && "main.php?log_in=1" >< result) {

      url = dir + '/tables.php';

      req = string("GET ",url," HTTP/1.1\r\n",
                   "Host: ", host,"\r\n",
                   "Cookie: ", c,"\r\n",
                   "\r\n");

      result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

      if("Available 'tickets ' tables" >< result && 'submit();"> user' >< result) {
        security_message(port:port);
        exit(0);
      }  

    }  

  }
}  
