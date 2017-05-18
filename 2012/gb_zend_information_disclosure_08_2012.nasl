###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zend_information_disclosure_08_2012.nasl 5700 2017-03-23 16:03:37Z cfi $
#
# Zend Framework 'application.ini' Information Disclosure Vulnerability
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

tag_summary = "Zend Framework is prone to an information-disclosure vulnerability.

Successful exploit of this issue allows an attacker to gain 
database credentials and more. Information obtained may aid in further attacks.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103554");
 script_version("$Revision: 5700 $");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_name("Zend Framework 'application.ini' Information Disclosure Vulnerability");
 script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/115906/Zend-Framework-Information-Disclosure.html");
 script_tag(name:"last_modification", value:"$Date: 2017-03-23 17:03:37 +0100 (Thu, 23 Mar 2017) $");
 script_tag(name:"creation_date", value:"2012-08-27 11:38:20 +0200 (Mon, 27 Aug 2012)");
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
   
port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/production/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + '/application/configs/application.ini';

  if( http_vuln_check( port:port, url:url, pattern:"\[production\]" ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
