###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_redis_server_default_password.nasl 2676 2016-02-17 09:05:41Z benallard $
#
# Redis Server Default Password
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = 'cpe:/a:redis:redis';

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.105289");
 script_version("$Revision: 2676 $");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Redis Server Default Password");
 script_tag(name:"last_modification", value:"$Date: 2016-02-17 10:05:41 +0100 (Wed, 17 Feb 2016) $");
 script_tag(name:"creation_date", value:"2015-06-05 15:47:46 +0200 (Fri, 05 Jun 2015)");
 script_summary("Determine if it is possible to login with the default password");
 script_category(ACT_ATTACK);
 script_family("Default Accounts");
 script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
 script_require_ports("Services/redis", 6379);

 script_tag(name: "summary" , value: 'The remote Redis server is prone to a default password authentication bypass vulnerability.');

 script_tag(name: "impact" , value:'This issue may be exploited by a remote attacker to gain
access to sensitive information or modify system configuration.');

 script_tag(name: "vuldetect" , value: 'Try to login with default password');
 script_tag(name: "insight" , value: 'It was possible to login with default password: foobared');
 script_tag(name: "solution" , value: 'Change the password.');
 script_dependencies("gb_redis_detect.nasl");

 script_tag(name:"qod_type", value:"exploit");

 script_mandatory_keys("redis/installed");

 exit(0);
}

include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );

if( ! get_kb_item( "redis/" + port + "/default_password" ) ) exit( 99 );

security_message( port:port );
exit( 0 );
