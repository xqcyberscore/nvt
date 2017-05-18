###############################################################################
# OpenVAS Vulnerability Test
# $Id: groupwise_web_interface_htmlver_hole.nasl 6053 2017-05-01 09:02:51Z teissa $
#
# GroupWise Web Interface 'HTMLVER' hole
#
# Authors:
# SecurITeam
#
# Copyright:
# Copyright (C) 2002 SecurITeam
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10873");
  script_version("$Revision: 6053 $");
  script_tag(name:"last_modification", value:"$Date: 2017-05-01 11:02:51 +0200 (Mon, 01 May 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2002-0341");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("GroupWise Web Interface 'HTMLVER' hole");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 SecurITeam");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"contact your vendor for a patch");
  script_tag(name:"summary", value:"By modifying the GroupWise Web Interface HTMLVER URL
  request, it is possible to gain additional information on the remote computer and even
  read local files from its hard drive");

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  foreach url( make_list( dir + "/GW5/GWWEB.EXE?GET-CONTEXT&HTMLVER=AAA",
                          dir + "/GWWEB.EXE?GET-CONTEXT&HTMLVER=AAA" ) ) {

    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req );

    if( "Could not find file SYS" >< buf ) {
      report = report_vuln_url( port:port, url:url) ;
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
