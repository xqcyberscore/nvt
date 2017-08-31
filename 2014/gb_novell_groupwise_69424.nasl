###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_groupwise_69424.nasl 6756 2017-07-18 13:31:14Z cfischer $
#
# Novell Groupwise 'FileUploadServlet' Arbitrary File Access Vulnerability
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

CPE = "cpe:/a:novell:groupwise";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.105078");
 script_bugtraq_id(69424);
 script_cve_id("CVE-2014-0600");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
 script_version ("$Revision: 6756 $");

 script_tag(name:"qod_type", value:"remote_app");

 script_name("Novell Groupwise 'FileUploadServlet' Arbitrary File Access Vulnerability");

 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69424");
 script_xref(name:"URL", value:"http://www.novell.com/groupwise/");
 script_xref(name:"URL", value:"http://www.novell.com/support/kb/doc.php?id=7015566");

 script_tag(name: "impact" , value:"An attacker can exploit this issue to retrieve or delete arbitrary
files, which may aid in further attacks.");

 script_tag(name: "vuldetect" , value:"Send a POST request and check the response");

 script_tag(name: "insight" , value:"FileUploadServlet in the Administration service allows remote attackers
to read or write to arbitrary files via the poLibMaintenanceFileSave paramete");

 script_tag(name: "solution" , value:"Updates are available. Please see the references or vendor advisory
for more information.");

 script_tag(name: "summary" , value:"Novell Groupwise is prone to an arbitrary file-access vulnerability.");
 script_tag(name: "affected" , value:"Novell GroupWise 2014 before SP1");
  
 script_tag(name:"last_modification", value:"$Date: 2017-07-18 15:31:14 +0200 (Tue, 18 Jul 2017) $");
 script_tag(name:"creation_date", value:"2014-09-03 15:23:42 +0200 (Wed, 03 Sep 2014)");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
 script_dependencies("gb_novell_groupwise_admin_console_detect.nasl");
 script_require_ports("Services/www", 9710);
 script_mandatory_keys("groupwise/admin_console/installed");

 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );

test = '------------------------OpenVAS\r\n' +
'Content-Disposition: form-data; name="poLibMaintenanceFileSave"\r\n' +
'\r\n' +
'OpenVAS_' + rand() + '_OpenVAS\r\n' +
'------------------------OpenVAS--';

len = strlen( test ) + 2;

host = http_host_name(port:port);

req = 'POST /gwadmin-console/gwAdminConsole/fileUpload HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'Accept: */*\r\n' +
      'User-Agent: ' + OPENVAS_HTTP_USER_AGENT  + '\r\n' +
      'Connection: Close\r\n' +
      'Content-Type: multipart/form-data; boundary=----------------------OpenVAS\r\n' +
      'Content-Length: ' + len + '\r\n' +
      '\r\n' +
      test;

result = http_send_recv( port:port, data:req );

if( "login.jsp" >< result ) exit( 99 );

if( "x-download" >< result && 'filename="gwcheck.opt"' >< result )
{
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
