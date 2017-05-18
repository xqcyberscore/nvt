###############################################################################
# OpenVAS Vulnerability Test
# $Id: mercuryboard_multiple_vuln.nasl 6040 2017-04-27 09:02:38Z teissa $
#
# Multiple Vulnerabilities in MercuryBoard
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2005 Noam Rathaus
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

# Multiple vulnerabilities in MercuryBoard 1.1.1
# "Alberto Trivero" <trivero@jumpy.it>
# 2005-01-24 23:37

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.16247");
  script_version("$Revision: 6040 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-27 11:02:38 +0200 (Thu, 27 Apr 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2005-0306", "CVE-2005-0307", "CVE-2005-0414", "CVE-2005-0460",
                "CVE-2005-0462", "CVE-2005-0662", "CVE-2005-0663", "CVE-2005-0878");
  script_bugtraq_id(12359, 12503, 12578, 12706, 12707, 12872);
  script_name("Multiple Vulnerabilities in MercuryBoard");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to MercuryBoard version 1.1.3.");
  script_tag(name:"summary", value:"The remote host is running MercuryBoard, a message board system written in PHP.

  Multiple vulnerabilities have been discovered in the product that allow an attacker to cause numerous cross site
  scripting attacks, inject arbitrary SQL statements and disclose the path under which the product has been installed.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/index.php";
  res = http_get_cache( item:url, port:port );

  if( "Powered by <a href='http://www.mercuryboard.com' class='small'><b>MercuryBoard</b></a>" >< res ) {
    if( egrep( pattern:'<b>MercuryBoard</b></a> \\[v(0\\..*|1\\.0\\..*|1\\.1\\.[0-2])\\]', string:res ) ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
