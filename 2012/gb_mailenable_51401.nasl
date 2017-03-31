###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mailenable_51401.nasl 3046 2016-04-11 13:53:51Z benallard $
#
# MailEnable 'ForgottonPassword.aspx' Cross Site Scripting Vulnerability
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

tag_summary = "MailEnable is prone to a cross-site scripting vulnerability because it
fails to properly sanitize user-supplied input.

An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may allow the attacker to steal cookie-based authentication
credentials and launch other attacks.

The following MailEnable versions are vulnerable: Professional,
Enterprise, and Premium 4.26 and prior versions Professional,
Enterprise, and Premium 5.52 and prior versions Professional,
Enterprise, and Premium 6.02 and prior versions";

tag_solution = "Vendor updates are available. Please see the references for details.";

if (description)
{
 script_id(103388);
 script_bugtraq_id(51401);
 script_cve_id("CVE-2012-0389");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_version("$Revision: 3046 $");

 script_name("MailEnable 'ForgottonPassword.aspx' Cross Site Scripting Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51401");
 script_xref(name : "URL" , value : "http://www.mailenable.com/");
 script_xref(name : "URL" , value : "http://www.mailenable.com/kb/Content/Article.asp?ID=me020567");

 script_tag(name:"last_modification", value:"$Date: 2016-04-11 15:53:51 +0200 (Mon, 11 Apr 2016) $");
 script_tag(name:"creation_date", value:"2012-01-13 10:03:24 +0100 (Fri, 13 Jan 2012)");
 script_summary("Determine if MailEnable is prone to a cross-site scripting vulnerability");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

dirs = make_list("/mail","/webmail",cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir, "/Mondo/lang/sys/login.aspx"); 

  if(http_vuln_check(port:port, url:url,pattern:"<title>MailEnable")) {

    url = string(dir,"/Mondo/lang/sys/ForgottenPassword.aspx?Username=></script><script>alert(/openvas-xss-test/)</script>");

    if(http_vuln_check(port:port, url:url,pattern:"<script>alert\(/openvas-xss-test/\)</script>",check_header:TRUE)) {
     
      security_message(port:port);
      exit(0);

    }  

  }
}

exit(0);

