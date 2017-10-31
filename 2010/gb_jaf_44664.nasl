###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jaf_44664.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# JAF CMS Multiple Remote File Include and Remote Shell Command Execution Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

tag_summary = "JAF CMS is prone to an shell-command-execution vulnerability and
multiple remote file-include vulnerabilities because the application
fails to properly sanitize user-supplied input.

An attacker can exploit the remote shell-command-execution issue
to execute arbitrary shell commands in the context of the
webserver process.

An attacker can exploit remote file-include issues to include
arbitrary remote files containing malicious PHP code and execute it in
the context of the webserver process. This may allow the attacker to
compromise the application and the underlying system; other attacks
are also possible.

JAF CMS 4.0 RC2 is vulnerable; other versions may also be affected.";

if(description)
{
 script_id(100895);
 script_version("$Revision: 7577 $");
 script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
 script_tag(name:"creation_date", value:"2010-11-05 13:21:25 +0100 (Fri, 05 Nov 2010)");
 script_bugtraq_id(44664);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("JAF CMS Multiple Remote File Include and Remote Shell Command Execution Vulnerabilities");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/44664");
 script_xref(name : "URL" , value : "http://jaf-cms.sourceforge.net/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/514625");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/514626");
 script_xref(name : "URL" , value : "http://www.htbridge.ch/advisory/rfi_in_jaf_cms.html");
 script_xref(name : "URL" , value : "http://www.htbridge.ch/advisory/shell_create__command_execution_in_jaf_cms.html");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
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

foreach dir( make_list_unique( "/jaf", "/cms", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  foreach file (keys(files)) {
   
    url = string(dir, "/module/forum/main.php?website=",crap(data:"../",length:3*9),files[file],"%00");

    if(http_vuln_check(port:port, url:url,pattern:file)) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
