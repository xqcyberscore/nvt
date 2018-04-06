# OpenVAS Vulnerability Test
# $Id: yacy_xss.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: YaCy Peer-To-Peer Search Engine XSS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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

tag_summary = "The remote host contains a peer-to-peer search engine that is prone to
cross-site scripting attacks. 

Description :

The remote host runs YaCy, a peer-to-peer distributed web search
engine and caching web proxy. 

The remote version of this software is vulnerable to multiple
cross-site scripting due to a lack of sanitization of user-supplied
data. 

Successful exploitation of this issue may allow an attacker to use the
remote server to perform an attack against a third-party user.";

tag_solution = "Upgrade to YaCy 0.32 or later.";

# Ref: Donato Ferrante <fdonato@autistici.org>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.16058");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");

  script_cve_id("CVE-2004-2651");
  script_bugtraq_id(12104);
  script_xref(name:"OSVDB", value:"12630");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  
  script_name("YaCy Peer-To-Peer Search Engine XSS");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/385453");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8080);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

buf = http_get(item:"/index.html?urlmaskfilter=<script>foo</script>", port:port);
r = http_keepalive_send_recv(port:port, data:buf);
if( r == NULL )exit(0);

if(r =~ "HTTP/1\.. 200" && egrep(pattern:"<title>YaCy.+ Search Page</title>.*<script>foo</script>", string:r))
{
  security_message(port);
  exit(0);
}
