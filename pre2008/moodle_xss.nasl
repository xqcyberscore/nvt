# OpenVAS Vulnerability Test
# $Id: moodle_xss.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Moodle XSS
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

tag_summary = "The remote host is using Moodle, a course management system (CMS).
There is a bug in this software that makes it vulnerable to cross 
site scripting attacks.

An attacker may use this bug to steal the credentials of the 
legitimate users of this site.";

# From: Bartek Nowotarski <silence10@wp.pl>
# Subject: Cross Site Scripting in Moodle < 1.3
# Date: 2004-04-30 23:34

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.12222");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2004-1978");
 script_bugtraq_id(10251);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_name("Moodle XSS");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
 script_family("Web application abuses");
 script_dependencies("gb_moodle_cms_detect.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("Moodle/Version");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);
if (  get_kb_item(string("www/", port, "/generic_xss")) ) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/moodle"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 loc = matches[2];
 req = http_get(item:string(loc, "/help.php?text=%3Cscript%3Efoo%3C/script%3E"),
                port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL ) exit(0);
 if(r =~ "HTTP/1\.. 200" && egrep(pattern:"<script>foo</script>", string:r))
 {
        security_message(port);
        exit(0);
 }
}
