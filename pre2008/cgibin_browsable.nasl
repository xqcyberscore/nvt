###############################################################################
# OpenVAS Vulnerability Test
# $Id: cgibin_browsable.nasl 4386 2016-10-31 07:02:07Z cfi $
#
# /cgi-bin directory browsable
#
# Authors:
# Hendrik Scholz <hendrik@scholz.net>
#
# Copyright:
# Copyright (C) 2000 Hendrik Scholz
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10039");
  script_version("$Revision: 4386 $");
  script_tag(name:"last_modification", value:"$Date: 2016-10-31 08:02:07 +0100 (Mon, 31 Oct 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("/cgi-bin directory browsable");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2000 Hendrik Scholz");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  tag_summary = "The /cgi-bin directory is browsable.
  This will show you the name of the installed common scripts
  and those which are written by the webmaster and thus may be
  exploitable.

  This NVT has been replaced by NVT 'Enabled Directory Listing Detection' (OID: 1.3.6.1.4.1.25623.1.0.111074).";

  tag_solution = "Make the /cgi-bin non-browsable.";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

exit(66);

port = get_http_port( default:80 );

dirs = NULL;
report_head = 'The following CGI directories are browsable:\n\n';

report_tail = '\nThis shows an attacker the name of the installed common scripts and those
which are written by the webmaster and thus may be exploitable.';

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/";

  buf = http_get_cache( item:url, port:port );

  if( ereg( pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:buf ) ) {

    buf = tolower( buf );
    if( dir == "" ) {
      must_see = "index of";
    } else {
      must_see = string( "<title>", dir );
    }

    if( must_see >< buf ) {
      dirs += report_vuln_url( port:port, url:url, url_only:TRUE ) + '\n';
    }
  }
}

if( dirs != NULL ) {
  security_message( port:port, data:report_head + dirs + report_tail );
  exit( 0 );
}

exit( 99 );
