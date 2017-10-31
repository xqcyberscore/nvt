###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_my_news_49818.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# MyNews 1.2 'basepath' Parameter Multiple Remote File Include Vulnerabilities
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

tag_summary = "MyNews 1.2 is prone to multiple remote file-include vulnerabilities
because the application fails to sufficiently sanitize user-
supplied input.

Exploiting these issues may allow a remote attacker to obtain
sensitive information or to execute arbitrary script code in the
context of the Web server process. This may allow the attacker to
compromise the application and the underlying computer; other attacks
are also possible.

MyNews 1.2 is vulnerable; other versions may also be affected.";

if (description)
{
 script_id(103281);
 script_version("$Revision: 7577 $");
 script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
 script_tag(name:"creation_date", value:"2011-09-29 13:17:07 +0200 (Thu, 29 Sep 2011)");
 script_bugtraq_id(49818);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("MyNews 1.2 'basepath' Parameter Multiple Remote File Include Vulnerabilities");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/49818");
 script_xref(name : "URL" , value : "http://mynews.magtrb.com/");
 script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/105352/mynews12-rfi.txt");
 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
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

foreach dir( make_list_unique( "/mynews", "/news", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  foreach file( keys( files ) ) {

    url = dir + "/includes/tiny_mce/plugins/filemanager/classes/FileManager/FileSystems/ZipFileImpl.php?basepath=/" + files[file] + "%00";

    if( http_vuln_check( port:port, url:url, pattern:file ) ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
