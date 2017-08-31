###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_54413.nasl 6720 2017-07-13 14:25:27Z cfischer $
#
# WordPress Global Content Blocks PHP Code Execution and Information Disclosure Vulnerabilities
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

tag_summary = "Global Content Blocks is prone to multiple security vulnerabilities,
including a remote PHP code-execution vulnerability and multiple information-
disclosure vulnerability.

Successful exploits of these issues may allow remote attackers to
execute arbitrary malicious PHP code in the context of the application
or obtain potentially sensitive information.

Global Content Blocks 1.5.1 is vulnerable; other versions may also
be affected.";

tag_solution = "Updates are available. Please see the references for details.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103516";
CPE = "cpe:/a:wordpress:wordpress";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(54413);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_version ("$Revision: 6720 $");

 script_name("WordPress Global Content Blocks PHP Code Execution and Information Disclosure Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/54413");
 script_xref(name : "URL" , value : "http://www.wordpress.org/");
 script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/49854");

 script_tag(name:"last_modification", value:"$Date: 2017-07-13 16:25:27 +0200 (Thu, 13 Jul 2017) $");
 script_tag(name:"creation_date", value:"2012-07-13 11:23:37 +0200 (Fri, 13 Jul 2012)");
 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("secpod_wordpress_detect_900182.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("wordpress/installed");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

url = dir + '/wp-content/plugins/global-content-blocks/resources/tinymce/gcb_ajax_add.php';

host = get_host_name();
ex = 'name=openvas_test&content=openvas_test&description=openvas_test&type=php';

len = strlen(ex);

req = string("POST ",url, " HTTP/1.1\r\n",
             "Host: ", host,"\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length:",len,"\r\n",
             "\r\n",
             ex);


result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE); 

if("openvas_test" >!< result && "php.png" >!< result)exit(0);

id = eregmatch(pattern:'"id":([0-9]+)',string:result);
if(isnull(id[1]))exit(0);

url = dir + '/wp-content/plugins/global-content-blocks/gcb/gcb_export.php?gcb=' + id[1];

if(http_vuln_check(port:port, url:url, pattern:"b3BlbnZhc190ZXN0")) {
  security_message(port:port);
  exit(0);
}  

exit(0);

