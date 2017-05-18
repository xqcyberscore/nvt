###############################################################################
# OpenVAS Vulnerability Test
# $Id: sgdynamo_path.nasl 6053 2017-05-01 09:02:51Z teissa $
#
# sgdynamo_path
#
# Authors:
# Scott Shebby (12/2003)
# Changes by rd :
#	- Description
#	- Support for multiple CGI directories
#	- HTTP KeepAlive support
#	- egrep() instead of eregmatch()
#
# Copyright:
# Copyright (C) 2003 Scott Shebby
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

# Ref:
# From: "Ruso, Anthony" <aruso@positron.qc.ca>
# To: Penetration Testers <PEN-TEST@SECURITYFOCUS.COM>
# Subject: Sgdynamo.exe Script -- Path Disclosure
# Date: Wed, 16 May 2001 11:55:32 -0400

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11954");
  script_version("$Revision: 6053 $");
  script_tag(name:"last_modification", value:"$Date: 2017-05-01 11:02:51 +0200 (Mon, 01 May 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("sgdynamo_path");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Scott Shebby");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  tag_summary = "The CGI 'sgdynamo.exe' can be tricked into giving the physical path to the
  remote web root.

  This information may be useful to an attacker who can use it to make better
  attacks against the remote server.";

  tag_solution = "None at this time";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"qod_type", value:"general_note");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/sgdynamo.exe?HTNAME=sgdynamo.exe";

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );

  if( res !~ "HTTP/1\.. 200" ) continue;

  path = egrep( pattern:"[aA-zZ]:\\.*sgdynamo\.exe", string:res );
  if( path ) {
    path = ereg_replace(string:path, pattern:".*([aA-zZ]:\\.*sgdynamo\.exe).*", replace:"\1");
    report = "It is possible to obtain the phyiscal path to the remote website by sending the following request :" +
             egrep( pattern:"^GET /", string:req ) +
             "We determined that the remote web path is : '" + path +
             "'This information may be useful to an attacker who can use it to make better attacks against the remote server.";
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
