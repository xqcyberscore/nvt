# OpenVAS Vulnerability Test
# $Id: spip_sql_injection.nasl 3362 2016-05-20 11:19:10Z antu123 $
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
 script_id(20978);
 script_version("$Revision: 3362 $");
 script_tag(name:"last_modification", value:"$Date: 2016-05-20 13:19:10 +0200 (Fri, 20 May 2016) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_cve_id("CVE-2006-0517", "CVE-2006-0518", "CVE-2006-0519");
 script_bugtraq_id(16458, 16461);
  
 name = "SPIP < 1.8.2-g SQL Injection and XSS Flaws";
 script_name(name);
 
 summary = "Checks for SPIP SQL injection flaw";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
  
 script_copyright("This script is Copyright (C) 2006 David Maciejak");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("http_version.nasl");
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

#
# the code
#

 include("http_func.inc");
 include("http_keepalive.inc");

 port = get_http_port(default:80);
 if(!get_port_state(port))exit(0);
 if (!can_host_php(port:port) ) exit(0);

 # Check a few directories.
 dirs = make_list("/spip", cgi_dirs());

 foreach dir (dirs)
 { 
  files=make_list("forum.php3", "forum.php");
  foreach file (files)
  {
        magic = rand();
	req = http_get(item:string(dir,"/",file,'?id_article=1&id_forum=-1/**/UNION/**/SELECT%20', magic, '/*'), port:port);
        res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
        if (res == NULL) exit(0);

        if (string('value="&gt; ', magic, '" class="forml"') >< res) {
          security_message(port:port);
	  exit(0);
	}
  }
}
