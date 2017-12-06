###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opencast_default_credentials.nasl 7996 2017-12-05 15:16:18Z cfischer $
#
# Opencast Default Credentials
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113058");
  script_version("$Revision: 7996 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-05 16:16:18 +0100 (Tue, 05 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-11-28 16:02:03 +0100 (Tue, 28 Nov 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("Opencast Default Credentials");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("gb_opencast_detect.nasl");
  script_mandatory_keys("opencast/detected");

  script_tag(name:"summary", value:"Opencast is using default administrative credentials.");
  script_tag(name:"vuldetect", value:"The script tries to log in using the default credentials.");
  script_tag(name:"insight", value:"Opencast has a default administrative account called 'admin' with the password 'opencast'.");
  script_tag(name:"impact", value:"If unchanged, an attacker can use the default credentials to log in and gain administrative privileges.");
  script_tag(name:"affected", value:"All Opencast versions.");
  script_tag(name:"solution", value:"Change the 'admin' account's password.");

  script_xref(name:"URL", value:"https://docs.opencast.org/r/3.x/admin/configuration/basic/");

  exit( 0 );
}

CPE = "cpe:/a:opencast:opencast";

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe: CPE, port: port ) ) exit( 0 );

req = http_get( port: port, item: dir + "/login.html");
res = http_keepalive_send_recv( port: port, data: req );

cookie = eregmatch( pattern: "Set-Cookie: JSESSIONID=([^;]+);", string: res, icase: TRUE );
if( !cookie[1] ) {
  exit( 0 );
}

data = "j_username=admin&j_password=opencast&_spring_security_remember_me=on";
accept_header = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8";
add_headers = make_array( "Cache-Control", "max-age=0", "Connection", "keep-alive", "Cookie", "JSESSIONID=" + cookie[1] , "Content-Type", "application/x-www-form-urlencoded" );

req = http_post_req( port: port, url: dir + "/j_spring_security_check", data: data, add_headers: add_headers, accept_header: accept_header );
res = http_keepalive_send_recv( port: port, data: req );

cookie = eregmatch( pattern: "Set-Cookie: SPRING_SECURITY_REMEMBER_ME_COOKIE=([^;])", string: res, icase: TRUE );
if( cookie[1] ) {
  report = "It was possible to log in to the Web Interface using the default user 'admin' with the default password 'opencast'.";
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
