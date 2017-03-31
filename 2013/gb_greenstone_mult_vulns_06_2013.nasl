###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_greenstone_mult_vulns_06_2013.nasl 2936 2016-03-24 08:30:15Z benallard $
#
# Greenstone Multiple Security Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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

tag_summary = "Greenstone is prone to the following security vulnerabilities:

1. A file-disclosure vulnerability
2. A cross-site scripting vulnerability
3. A security weakness
4. A security-bypass vulnerability

Attackers can exploit these issues to view local files, bypass certain
security restriction, steal cookie-based authentication, or execute
arbitrary scripts in the context of the browser.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103727";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(56662);
 script_version ("$Revision: 2936 $");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_name("Greenstone Multiple Security Vulnerabilities");

 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56662");
 
 script_tag(name:"last_modification", value:"$Date: 2016-03-24 09:30:15 +0100 (Thu, 24 Mar 2016) $");
 script_tag(name:"creation_date", value:"2013-06-03 13:45:05 +0200 (Mon, 03 Jun 2013)");
 script_summary("Determine if it is possible to read the users.gdb");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

dirs = make_list("/gsdl","/greenstone", cgi_dirs());

foreach dir (dirs) {

  url = dir + '/etc/users.gdb';
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

  if("<groups>" >< buf && "<password>" >< buf && "<username>" >< buf) {

    security_message(port:port);
    exit(0);

  }  

}

exit(0);
