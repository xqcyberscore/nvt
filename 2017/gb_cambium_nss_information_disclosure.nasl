###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cambium_nss_information_disclosure.nasl 7951 2017-11-30 14:04:23Z asteins $
#
# Cambium Networks Services Server Information Disclosure Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.113060");
  script_version("$Revision: 7951 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-30 15:04:23 +0100 (Thu, 30 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-11-30 11:49:50 +0100 (Thu, 30 Nov 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Cambium Networks Services Server Information Disclosure Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_cambium_networks_services_server_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("cambium-networks/services-server/detected");

  script_tag(name:"summary", value:"Cambium Networks Services Server allows unauthenticated users to access sensitive files and directories.");
  script_tag(name:"vuldetect", value:"The script tries to access the critical files and directories.");
  script_tag(name:"insight", value:"Cambium Networks Services Server does not implement strict access control. This allows an unauthenticated attacker to access sensitive information, such as credentials.");
  script_tag(name:"impact", value:"The accessible files include user names and password hashes, potentially allowing an attacker to gain login credentials.");
  script_tag(name:"affected", value:"Cambium Networks Services Server - all versions");
  script_tag(name:"solution", value:"No solution available as of 30th November 2017. This will be updated once a solution is available.");

  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/3526");

  exit( 0 );
}

CPE = "cpe:/a:cambium-networks:services-server";

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe: CPE, port: port ) ) exit( 0 );

if( dir == "/" ) dir = "";

files = make_list( "/httpd.conf", "/windows/apache2/conf/server.key", "/windows/apache2/conf/server.pem", "/windows/apache2/conf/httpd.conf",
                   "/stack/php/php.ini", "/windows/php/php.ini",
                   "/stack/postgresql/data/pg_hba.conf", "/stack/postgresql/data/postgresql.conf",
                   "/logs/",
                   "/scripts/cnss_test_users.sql", "/scripts/cnss_seed_users.sql" );

file_list = "";
foreach file ( files ) {
  res = http_get_cache( port: port, item: dir + file);

  if( "200 OK" >< res ) {
    VULN = TRUE;
    file_list += file + '\r\n';
  }
}

if( VULN ) {
  report = 'It was possible to access the following sensitive files and directories:\r\n' + file_list;
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
