###############################################################################
# OpenVAS Vulnerability Test
# $Id: DDI_Netscape_Enterprise_Default_Administrative_Password.nasl 6056 2017-05-02 09:02:50Z teissa $
#
# Netscape Enterprise Default Administrative Password
#
# Authors:
# Forrest Rae <forrest.rae@digitaldefense.net>
#
# Copyright:
# Copyright (C) 2003 Digital Defense Inc.
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
  script_oid("1.3.6.1.4.1.25623.1.0.11208");
  script_version("$Revision: 6056 $");
  script_tag(name:"last_modification", value:"$Date: 2017-05-02 11:02:50 +0200 (Tue, 02 May 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-1999-0502");
  script_name("Netscape Enterprise Default Administrative Password");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Digital Defense Inc.");
  script_family("Default Accounts");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Netscape_iPlanet/banner");
  script_require_ports("Services/www", 8888);
  script_exclude_keys("Settings/disable_cgi_scanning");

  tag_summary = "This host is running the Netscape Enterprise Server. The Administrative
  interface for this web server, which operates on port 8888/TCP, is using
  the default username and password of 'admin'.";

  tag_impact = "An attacker can use this to reconfigure the web server, cause a denial
  of service condition, or gain access to this host.";

  tag_solution = "Please assign the web administration console a difficult to guess
  password.";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:8888 );

banner = get_http_banner( port:port );

if( ! banner || ( "Netscape" >!< banner && "iPlanet" >!< banner ) ) exit( 0 );

url = "/https-admserv/bin/index";
req = http_get( item:url, port:port );
req = req - string( "\r\n\r\n" );
# HTTP auth = "admin:admin"
req = string( req, "\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\n\r\n" );
res = http_keepalive_send_recv( port:port, data:req );

if( "Web Server Administration Server" >< res && "index?tabs" >< res ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report);
  exit( 0 );
}

exit( 99 );
