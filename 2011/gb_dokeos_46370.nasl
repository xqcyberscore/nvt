###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dokeos_46370.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Dokeos 'style' Parameter Cross Site Scripting Vulnerability
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

tag_summary = "Dokeos is prone to a cross-site scripting vulnerability because it
fails to properly sanitize user-supplied input.

An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may let the attacker steal cookie-based authentication
credentials and launch other attacks.

Dokeos 1.8.6.2 is vulnerable; other versions may also be affected.";

tag_solution = "Currently, we are not aware of any vendor-supplied patches. If you
feel we are in error or if you are aware of more recent information,
please mail us at: vuldb@securityfocus.com.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103075");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-02-15 13:44:44 +0100 (Tue, 15 Feb 2011)");
 script_bugtraq_id(46370);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

 script_name("Dokeos 'style' Parameter Cross Site Scripting Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/46370");
 script_xref(name : "URL" , value : "http://www.dokeos.com/");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("dokeos_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!dir = get_dir_from_kb(port:port, app:"dokeos"))exit(0);

url = string(dir, '/main/inc/latex.php?code="style="top:0;position:absolute;width:9999px;height:9999px;"onmouseover%3d"alert(',"'openvas-xss-test'",')"'); 

if(http_vuln_check(port:port, url:url,pattern:"onmouseover=.alert\('openvas-xss-test'\)", check_header:TRUE)) {
     
  security_message(port:port);
  exit(0);

}

exit(0);

