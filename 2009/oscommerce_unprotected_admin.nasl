###############################################################################
# OpenVAS Vulnerability Test
# $Id: oscommerce_unprotected_admin.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# osCommerce unprotected admin directory
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

tag_summary = "This host is running osCommerce, a widely installed open source shopping e-commerce solution.
  See http://www.oscommerce.com for more information.

  The store admin directory on your server needs to be password protected using .htaccess.
  Most of the time the server you are hosting your store on has the ability to password protect
  directories through the server administration area so check with your host.";

tag_solution = "Limit access to the directory using .htaccess.
  See http://www.oscommerce.info/docs/english/e_post-installation.html for further Information.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100003");
 script_version("$Revision: 9350 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2009-02-26 04:52:45 +0100 (Thu, 26 Feb 2009)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

 script_name("osCommerce unprotected admin directory");
 script_tag(name:"qod_type", value:"remote_analysis");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("oscommerce_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("Software/osCommerce");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

CPE = 'cpe:/a:oscommerce:oscommerce';

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

url = string(dir, "/admin/customers.php");
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if( buf == NULL )exit(0);
if ( ereg(pattern: "^HTTP/1\.[01] +200", string: buf) &&
     egrep(pattern: 'href=.*http.*?gID=.*&selected_box=.*&osCAdminID=', string: buf)
   ) 
  {    
   security_message(port:port);
   exit(0);
  }

exit(0);
