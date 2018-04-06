##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_joomla_com_xmap_sql_inj_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Joomla com_xmap SQL Injection Vulnerability
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

tag_impact = "Successful exploitation will let attackers to manipulate SQL queries by
  injecting arbitrary SQL code.
  Impact Level: Application.";
tag_affected = "Joomla Xmap component version 1.2.11";
tag_insight = "The flaw is due to input passed via 'view' parameter to
  'index.php' is not properly sanitised before being used in a SQL query.";
tag_solution = "Upgrade to Joomla Xmap component version 1.2.12 or later
  For updates refer to http://joomlacode.org/gf/project/xmap/frs/?action=FrsReleaseBrowse&frs_package_id=3882";
tag_summary = "This host is running Joomla xmap component and is prone to SQL
  injection vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902397");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-07-22 12:16:19 +0200 (Fri, 22 Jul 2011)");
  script_bugtraq_id(48658);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Joomla com_xmap SQL Injection Vulnerability");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/103010/joomlaxmap1211-sql.txt");

  script_tag(name:"qod_type", value:"remote_active");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("joomla/installed");
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

## Get the port
joomlaPort = get_http_port(default:80);
if(!joomlaPort){
  exit(0);
}

## Get the application directiory
if(!joomlaDir = get_dir_from_kb(port:joomlaPort, app:"joomla")){
  exit(0);
}

sndReq = http_get(item:string(joomlaDir, "/index.php?option=com_xmap&tmpl=" +
                  "component&Itemid=999&view='"), port:joomlaPort);
rcvRes = http_send_recv(port:joomlaPort, data:sndReq);

## Check the response to confirm vulnerability
if('>Warning<' >< rcvRes && 'Invalid argument supplied' >< rcvRes){
  security_message(joomlaPort);
}
