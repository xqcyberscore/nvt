# OpenVAS Vulnerability Test
# $Id: yabb_xss.nasl 6046 2017-04-28 09:02:54Z teissa $
# Description: YaBB XSS and Administrator Command Execution
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
# Fixes by Tenable:
#   - added CVE xrefs.
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

#  Ref: GulfTech Security <security@gulftech.org>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14782");
  script_version("$Revision: 6046 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-28 11:02:54 +0200 (Fri, 28 Apr 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-2402", "CVE-2004-2403");
  script_bugtraq_id(11214, 11215);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("YaBB XSS and Administrator Command Execution");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "cross_site_scripting.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2004-09/0227.html");

  script_tag(name:"solution", value:"Unknown at this time.");
  script_tag(name:"summary", value:"The 'YaBB.pl' CGI is installed. This version is affected by a
  cross-site scripting vulnerability.  This issue is due to a failure of
  the application to properly sanitize user-supplied input. 

  As a result of this vulnerability, it is possible for a remote
  attacker to create a malicious link containing script code that will
  be executed in the browser of an unsuspecting user when followed. 

  Another flaw in YaBB may allow an attacker to execute malicious
  administrative commands on the remote host by sending malformed IMG
  tags in posts to the remote YaBB forum and waiting for the forum
  administrator to view one of the posts.");

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port( default:80 );

if( get_kb_item( "www/" + port + "/generic_xss" ) ) exit( 0 );

foreach dir( make_list_unique( "/yabb", "/forum", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  url = dir + "/YaBB.pl?board=;action=imsend;to=%22%3E%3Cscript%3Efoo%3C/script%3E";

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );

  if( res =~ "HTTP/1\.. 200" && egrep( pattern:"<script>foo</script>", string:res ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
