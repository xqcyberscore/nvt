# OpenVAS Vulnerability Test
# $Id: spip_sql_injection.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: SPIP < 1.8.2-g SQL Injection and XSS Flaws
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2006 David Maciejak
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

tag_summary = "The remote web server has a PHP application that is affected by
multiple flaws. 

Description:

The remote host is running SPIP, an open-source CMS written in PHP. 

The remote version of this software is prone to SQL injection and
cross site scripting attacks.  An attacker could send specially
crafted URL to modify SQL requests, for example, to obtain the admin
password hash, or execute malicious script code on the remote system.";

tag_solution = "Upgrade to SPIP version 1.8.2-g or later.";

# Ref: Siegfried and netcraft

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.20978");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2006-0517", "CVE-2006-0518", "CVE-2006-0519");
 script_bugtraq_id(16458, 16461);
 script_name("SPIP < 1.8.2-g SQL Injection and XSS Flaws");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_copyright("This script is Copyright (C) 2006 David Maciejak");
 script_family("Web application abuses");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.zone-h.org/en/advisories/read/id=8650/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/423655/30/0/threaded");
 script_xref(name : "URL" , value : "http://listes.rezo.net/archives/spip-en/2006-02/msg00002.html");
 script_xref(name : "URL" , value : "http://listes.rezo.net/archives/spip-en/2006-02/msg00004.html");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port) ) exit(0);

files = make_list( "/forum.php3", "/forum.php" );

foreach dir( make_list_unique( "/spip", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  foreach file( files ) {

    magic = rand();
    url = string(dir,file,'?id_article=1&id_forum=-1/**/UNION/**/SELECT%20', magic, '/*');
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) continue;

    if (string('value="&gt; ', magic, '" class="forml"') >< res) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );