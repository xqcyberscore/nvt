###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_asp_cms_54100.nasl 3014 2016-04-08 10:04:54Z benallard $
#
# ASP Content Management Database Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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

tag_summary = "ASP Content Management is prone to an information-disclosure
vulnerability.

An attacker can exploit this issue to gain access to the database file
stored on the web server. Information harvested may aid in launching
further attacks.";


if (description)
{
 script_id(103497);
 script_bugtraq_id(54100);
 script_version ("$Revision: 3014 $");

 script_name("ASP Content Management Database Information Disclosure Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/54100");

 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"last_modification", value:"$Date: 2016-04-08 12:04:54 +0200 (Fri, 08 Apr 2016) $");
 script_tag(name:"creation_date", value:"2012-06-21 08:49:16 +0200 (Thu, 21 Jun 2012)");
 script_summary("Determine if it is possible to read news_data.mdb");
 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_asp(port:port))exit(0);

dirs = make_list("/cms",cgi_dirs());

foreach dir (dirs) {
   
    url = string(dir, "/news/news_data.mdb"); 
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

    if("Jet DB" >< buf) {
      security_message(port:port); 
      exit(0);
    }
}

exit(0);
