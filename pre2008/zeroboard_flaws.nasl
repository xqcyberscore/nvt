# OpenVAS Vulnerability Test
# $Id: zeroboard_flaws.nasl 3520 2016-06-15 04:22:26Z ckuerste $
# Description: Zeroboard flaws
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

tag_summary = "The remote web server contains several PHP scripts that are prone to
arbitrary PHP code execution and cross-site scripting attacks. 

Description :

The remote host runs Zeroboard, a web BBS application popular in
Korea. 

The remote version of this software is vulnerable to cross-site
scripting and remote script injection due to a lack of sanitization of
user-supplied data. 

Successful exploitation of this issue may allow an attacker to execute
arbitrary code on the remote host or to use it to perform an attack
against third-party users.";

tag_solution = "Upgrade to Zeroboard 4.1pl5 or later.";

# Ref: Jeremy Bae

if(description)
{
  script_id(16059);
  script_version("$Revision: 3520 $");
  script_tag(name:"last_modification", value:"$Date: 2016-06-15 06:22:26 +0200 (Wed, 15 Jun 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-1419");
  script_bugtraq_id(12103);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  
  script_name("Zeroboard flaws");

  script_summary("Checks for Zeroboard flaws");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://marc.theaimsgroup.com/?l=bugtraq&m=110391024404947&w=2");
  exit(0);
}

#the code

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if ( ! get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

dirs = make_list("/bbs", cgi_dirs());

foreach dir (dirs) {
  req = http_get(item:string(dir, "/check_user_id.php?user_id=<script>foo</script>"), port:port);
  r = http_keepalive_send_recv(port:port, data:req);
  if( r == NULL )exit(0);

  if(r =~ "HTTP/1\.. 200" && "ZEROBOARD.COM" >< r && "<script>foo</script>" >< r)
  {
    security_message(port);
    exit(0);
  }
}
