###############################################################################
# OpenVAS Vulnerability Test
# $Id: apache_server_status.nasl 6040 2017-04-27 09:02:38Z teissa $
# Description: Apache /server-status accessible
#
# Authors:
# Vincent Renardias <vincent@strongholdnet.com>
#
# Copyright:
# Copyright (C) 2001 StrongHoldNet
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
#
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10677");
  script_version("$Revision: 6040 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-27 11:02:38 +0200 (Thu, 27 Apr 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Apache /server-status accessible");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2001 StrongHoldNet");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "apache_server_info.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/apache");

  script_tag(name:"summary", value:"Leak of information in Apache.");
  script_tag(name:"vuldetect", value:"Check if /server-status page exist.");
  script_tag(name:"solution", value:"If you don't use this feature, comment the appropriate section in
  your httpd.conf file. If you really need it, limit its access to the administrator's machine.");
  script_tag(name:"insight", value:"server-status is a built-in Apache HTTP Server handler used to
  retrieve the server's status report.");
  script_tag(name:"affected", value:"All Apache version.");
  script_tag(name:"impact", value:"Requesting the URI /server-status gives information about
  the currently running Apache.");

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

url = "/server-status";

req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req );

if( "Apache Server Status" >< buf ) {

  if( ! get_kb_item( 'www/server-info/banner/' + port ) ) {
    sv = eregmatch( pattern:'Server Version: (Apache/[^<]+)', string:buf );
    if( ! isnull( sv[1] ) )
      set_kb_item( name:'www/server-info/banner/' + port, value:'Server: ' + sv[1] );
  }

  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );