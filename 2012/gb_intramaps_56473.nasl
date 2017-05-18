###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_intramaps_56473.nasl 5714 2017-03-24 10:52:48Z cfi $
#
# Intramaps Multiple Security Vulnerabilities
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

tag_summary = "Intramaps is prone to multiple security vulnerabilities including:

1. Multiple cross-site scripting vulnerabilities
2. Multiple SQL-injection vulnerabilities
3. An information-disclosure vulnerability
4. A cross-site request-forgery vulnerability
5. An XQuery-injection vulnerability

An attacker can exploit these vulnerabilities to execute arbitrary
script code in the browser of an unsuspecting user in the context of
the affected site, steal cookie-based authentication credentials,
access or modify data, exploit vulnerabilities in the underlying
database, disclose sensitive information, and perform unauthorized
actions. Other attacks are also possible.

Intramaps 7.0.128 Rev 318 is vulnerable; other versions may also
be affected.";

tag_solution = "Reportedly these issues are fixed. Please contact the vendor for more
information.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103605");
 script_bugtraq_id(56473);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_version ("$Revision: 5714 $");
 script_name("Intramaps Multiple Security Vulnerabilities");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/56473");
 script_xref(name : "URL" , value : "http://www.stratsec.net/Research/Advisories/Intramaps-Multiple-Vulnerabilities-%28SS-2012-007%29");
 script_tag(name:"last_modification", value:"$Date: 2017-03-24 11:52:48 +0100 (Fri, 24 Mar 2017) $");
 script_tag(name:"creation_date", value:"2012-11-12 10:40:31 +0100 (Mon, 12 Nov 2012)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
   
port = get_http_port( default:80 );

subdirs = make_list("/applicationengine","/ApplicationEngine/");

foreach dir( make_list_unique( "/IntraMaps", "/intramaps75", "/IntraMaps70", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  foreach subdir (subdirs) {
   
    url = dir + subdir + '/'; 

    if( http_vuln_check( port:port, url:url, pattern:"<title>IntraMaps" ) ) {
    
      url = dir + subdir + "/Application.aspx?project=NAME</script><script>alert('openvas-xss-test')</script>";

      if(http_vuln_check(port:port, url:url, pattern:"<script>alert\('openvas-xss-test'\)</script>", check_header:TRUE ) ) {
        report = report_vuln_url( port:port, url:url );
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

exit( 99 );
