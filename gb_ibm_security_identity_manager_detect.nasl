###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_security_identity_manager_detect.nasl 10294 2018-06-22 06:20:56Z santu $
#
# IBM Security Identity Manager Detection
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation;
# either version 2 of the License, or (at your option) any later version.
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813523");
  script_version("$Revision: 10294 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-06-22 08:20:56 +0200 (Fri, 22 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-06-12 17:05:24 +0530 (Tue, 12 Jun 2018)");
  script_name("IBM Security Identity Manager Detection");

  script_tag(name:"summary" , value:"Detection of installed path and version of
  IBM Security Identity Manager.   

  The script sends HTTP GET requests and try to confirm the IBM Security Identity
  Manager installation and sets the results in KB.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443, 80);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:443 );

banner = http_get_cache( item:"/itim/self/jsp/logon/login.jsp", port:port );

if( "IBM Security Identity Manager" >!< banner ) exit( 0 );

version = 'unknown';

vers = eregmatch( pattern:'IBM Security Identity Manager v([0-9.]+)', string:banner );

if(!isnull( vers[1] ) ) {
  version = vers[1];
  set_kb_item(name: "ibm_security_identity_manager/version", value: version);
}

set_kb_item( name:"ibm_security_identity_manager/installed",value:TRUE );

cpe = build_cpe( value:version, exp:"^([.0-9.]+)", base:"cpe:/a:ibm:security_identity_manager:" );
if( isnull(cpe))
  cpe = "cpe:/a:ibm:security_identity_manager";

register_product( cpe:cpe, location:'/', port:port );

log_message( data: build_detection_report( app:"IBM Security Identity Manager",
                                           version:version,
                                           install:'/',
                                           cpe:cpe,
                                           concluded: vers[0] ),
                                           port:port );
exit(0);
