###############################################################################
# OpenVAS Vulnerability Test
# $Id: sonicwall_soho_10_xss.nasl 9087 2018-03-12 17:24:24Z cfischer $
#
# SonicWall SOHO Web Interface XSS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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
###############################################################################

# Ref: Oliver Karow <Oliver Karow gmx de>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.17972");
  script_version("$Revision: 9087 $");
  script_name("SonicWall SOHO Web Interface XSS");
  script_tag(name:"last_modification", value:"$Date: 2018-03-12 18:24:24 +0100 (Mon, 12 Mar 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2005-1006");
  script_bugtraq_id(12984);
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_require_ports("Services/www",80);
  script_dependencies("find_service.nasl", "http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.sonicwall.com/");

  tag_summary = "The remote host is a SonicWall SOHO appliance.

  This version is vulnerable to multiple flaws, and in particular to a
  cross-site scripting due to a lack of sanitization of user-supplied data.
  Successful exploitation of this issue may allow an attacker to execute
  malicious script code on a vulnerable appliance.";

  tag_solution = "Upgrade to the latest version.";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

if( get_kb_item( "www/" + port + "/generic_xss" ) ) exit( 0 );

url = "/<script>foo</script>";
buf = http_get( item:url, port:port );
r = http_keepalive_send_recv( port:port, data:buf );
if( r == NULL ) exit( 0 );

#if(egrep(pattern:"<title>SonicWall</title>.*<script>foo</script>", string:r))
if( r =~ "HTTP/1\.. 200" && egrep( pattern:"SonicWall", string:r, icase:TRUE ) &&
    egrep( pattern:"<script>foo</script>", string:r ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
