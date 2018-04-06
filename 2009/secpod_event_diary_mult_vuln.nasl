##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_event_diary_mult_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# ASP-Dev XM Event Diary Multiple Vulnerabilities
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

tag_summary = "The host is running ASP-Dev XM Events Diary and prone to multiple
  vulnerabilities.

  Vulnerabilities Insight:
  - Input passed to the 'cat' parameter in 'default.asp' and 'diary_viewC.asp'
    are not properly sanitised before being used in SQL queries.
  - Insufficient access control to the database file 'diary.mdb' which is being
    used for Events Diary web application.";

tag_impact = "Successful exploitation will let the attacker execute arbitrary codes in the
  in the context of the web application or can execute sql injection attack
  to gain sensitive information about the database engine and table structures.
  Impact Level: Application";
tag_affected = "ASP-Dev XM Event Diary Multiple Vulnerabilities";
tag_solution = "No solution or patch was made available for at least one year since disclosure
  of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900452");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-01-30 14:33:42 +0100 (Fri, 30 Jan 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-5923", "CVE-2008-5924", "CVE-2008-5925");
  script_bugtraq_id(32809);
  script_name("ASP-Dev XM Event Diary Multiple Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33152");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!port){
  port = 80;
}

request = string("GET /diary/default.asp \r\n",
                 "Host: ", get_host_name(), "\r\n");
response = http_keepalive_send_recv(port:port, data:request);

if("Powered by ASP-DEv XM Diary" >< response)
{
  request = string("GET /diary/default.asp?cat=testing' \r\n",
                   "Host: ", get_host_name(), "\r\n");
  response = http_keepalive_send_recv(port:port, data:request);
  if("Microsoft JET Database Engine" >< response &&
     "Syntax error in string" >< response){
    security_message(port);
  }
}
