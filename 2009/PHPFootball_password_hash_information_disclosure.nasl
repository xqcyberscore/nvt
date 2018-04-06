###############################################################################
# OpenVAS Vulnerability Test
# $Id: PHPFootball_password_hash_information_disclosure.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# PHPFootball 'filter.php' Password Hash Information Disclosure
# Vulnerability
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

tag_summary = "PHPFootball is prone to an information-disclosure vulnerability
  because it fails to properly sanitize user-supplied input.

  An attacker can exploit this vulnerability to obtain sensitive
  information that may lead to further attacks.

  PHPFootball 1.6 is vulnerable; other versions may also be affected.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100016");
 script_version("$Revision: 9350 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2009-03-06 13:13:19 +0100 (Fri, 06 Mar 2009)");
 script_bugtraq_id(33087);
 script_cve_id("CVE-2009-0711");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_name("PHPFootball 'filter.php' Password Hash Information Disclosure Vulnerability");
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port)) exit(0);

foreach dir( make_list_unique( "/phpfootball", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string(dir, "/filter.php?dbtable=Accounts&dbfield=Password");

  if(http_vuln_check(port:port, url:url,pattern:"<td class=td>[a-f0-9]{32}</td>")) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );