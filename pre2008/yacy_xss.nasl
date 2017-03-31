# OpenVAS Vulnerability Test
# $Id: yacy_xss.nasl 3520 2016-06-15 04:22:26Z ckuerste $
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
  script_id(16058);
  script_version("$Revision: 3520 $");
  script_tag(name:"last_modification", value:"$Date: 2016-06-15 06:22:26 +0200 (Wed, 15 Jun 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");

  script_cve_id("CVE-2004-2651");
  script_bugtraq_id(12104);
  script_xref(name:"OSVDB", value:"12630");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  
  script_name("YaCy Peer-To-Peer Search Engine XSS");

  script_summary("Checks for YaCy Peer-To-Peer Search Engine XSS");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_require_ports("Services/www", 8080);
  script_dependencies("cross_site_scripting.nasl");
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/385453");
  exit(0);
}

#the code

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8080);
if ( ! get_port_state(port))exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

buf = http_get(item:"/index.html?urlmaskfilter=<script>foo</script>", port:port);
r = http_keepalive_send_recv(port:port, data:buf);
if( r == NULL )exit(0);

if(r =~ "HTTP/1\.. 200" && egrep(pattern:"<title>YaCy.+ Search Page</title>.*<script>foo</script>", string:r))
{
  security_message(port);
  exit(0);
}
