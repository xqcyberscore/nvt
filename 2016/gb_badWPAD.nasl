###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_badWPAD.nasl 3805 2016-08-05 15:43:58Z mime $
#
# badWPAD
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.105845");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_version ("$Revision: 3805 $");
 script_tag(name:"last_modification", value:"$Date: 2016-08-05 17:43:58 +0200 (Fri, 05 Aug 2016) $");
 script_tag(name:"creation_date", value:"2016-08-05 14:58:54 +0200 (Fri, 05 Aug 2016)");
 script_name("badWPAD");

 script_tag(name: "summary" , value: "The remote host is serving a Web Proxy Auto-Discovery Protocol config file.
The Web Proxy Auto-Discovery Protocol (WPAD) is a method used by clients to locate the URL of a configuration file using DHCP and/or DNS discovery methods.
Once detection and download of the configuration file is complete, it can be executed to determine the proxy for a specified URL.

There are known security issues with WPAD. See http://www.trendmicro.co.uk/media/misc/wp-badwpad.pdf for more information.");

 script_tag(name:"qod_type", value:"remote_banner_unreliable");

 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

url = '/wpad.dat';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "Content-Type: application/x-ns-proxy-autoconfig" >< buf && "FindProxyForURL" >< buf )
{
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 0 );

