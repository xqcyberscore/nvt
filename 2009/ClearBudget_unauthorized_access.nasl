###############################################################################
# OpenVAS Vulnerability Test
# $Id: ClearBudget_unauthorized_access.nasl 4574 2016-11-18 13:36:58Z teissa $
#
# ClearBudget Invalid '.htaccess' Unauthorized Access Vulnerability
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

tag_summary = "ClearBudget is prone to an unauthorized-access vulnerability because
  it fails to properly restrict access to certain directories.

  An attacker can exploit this vulnerability to gain access to
  database contents. Information harvested can lead to further
  attacks.

  ClearBudget 0.6.1 is vulnerable; other versions may also be affected.";

tag_solution = "The vendor released an update to address this issue. Please see http://clearbudget.douteaud.com/
  for more information.";

if (description)
{
 script_id(100010);
 script_version("$Revision: 4574 $");
 script_tag(name:"last_modification", value:"$Date: 2016-11-18 14:36:58 +0100 (Fri, 18 Nov 2016) $");
 script_tag(name:"creation_date", value:"2009-03-06 13:13:19 +0100 (Fri, 06 Mar 2009)");
 script_bugtraq_id(33643);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_name("ClearBudget Invalid '.htaccess' Unauthorized Access Vulnerability");
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);

dir = make_list("/ClearBudget","/cb", cgi_dirs());

foreach d (dir)
{
 url = string(d, "/db/budget.sqlite");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly: FALSE);
 if( buf == NULL )exit(0);
 if (ereg(pattern: "^HTTP/1\.[01] +200", string: buf) && "SQLite" >< buf)
   {
    security_message(port:port);
    exit(0);
 }
}

exit(0);
