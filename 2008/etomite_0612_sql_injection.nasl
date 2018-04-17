# OpenVAS Vulnerability Test
# $Id: etomite_0612_sql_injection.nasl 9502 2018-04-17 07:42:19Z cfischer $
# Description: Etomite CMS id Parameter SQL Injection
#
# Authors:
# Justin Seitz <jms@bughunter.ca>
#
# Copyright:
# Copyright (C) 2006 Justin Seitz
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

tag_summary = "The remote web server contains a PHP script that is affected by a SQL
injection vulnerability. 

Description:

The remote web server is running Etomite CMS, a PHP-based content
management system. 

The version of Etomite CMS installed on the remote host fails to
sanitize input to the 'id' parameter before using it in the
'index.php' script in a database query.  Provided PHP's
'magic_quotes_gpc' setting is disabled, an unauthenticated attacker
can exploit this issue to manipulate SQL queries, possibly leading to
disclosure of sensitive data, attacks against the underlying database,
and the like.";

tag_solution = "No patches or upgrades have been reported by the vendor at this time.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.80057");
 script_version("$Revision: 9502 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-17 09:42:19 +0200 (Tue, 17 Apr 2018) $");
 script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2006-6048");
 script_bugtraq_id(21135);
 script_xref(name:"OSVDB", value:"30442");
 script_name("Etomite CMS id Parameter SQL Injection");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_copyright("This script is Copyright (C) 2006 Justin Seitz");
 script_family("Web application abuses");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/451838/30/0/threaded");

 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port)) exit(0);

injectstring = rand_str(charset:"abcdefghijklmnopqrstuvwxyz0123456789_", length:10);

foreach dir( make_list_unique( "/etomite", "/cms", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string(dir, "/index.php?id=", injectstring, "'");
  req = http_get(item:url,port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) continue;
	
  sqlstring = "";
  if(string("etomite_site_content.id = '", injectstring) >< res) {
    if (report_verbosity > 1) {
      sqlstring = res;
      if("<span id='sqlHolder'>" >< sqlstring) sqlstring = strstr(sqlstring,"SELECT");
      if("</span></b>" >< sqlstring) sqlstring = sqlstring - strstr(sqlstring, "</span></b>");			
      info = string("The version of Etomite CMS installed in directory '", dir, "'\n",
                    "is vulnerable to this issue. Here is the resulting SQL string\n",
                    "from the remote host when using a test string of '",injectstring,"'  :\n\n", sqlstring);
    }
    else info = "";

    security_message(data:info, port:port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}

exit( 99 );