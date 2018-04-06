###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trixbox_info_disc_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Trixbox Information Disclosure Vulnerability
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

tag_impact = "Successful exploitation allows attackers to obtain valid
usernames, which may aid them in brute-force password cracking or other
attacks.

Impact Level: Application";

tag_affected = "Trixbox version 2.8.0.4 and prior.";

tag_insight = "The flaw is due to Trixbox returning valid usernames via a http
GET request to a Flash Operator Panel(FOP) file.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "The host is running Trixbox and is prone to information disclosure
vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802210");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-07-13 17:31:13 +0200 (Wed, 13 Jul 2011)");
  script_bugtraq_id(48503);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Trixbox Information Disclosure Vulnerability");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/102627/trixboxfop-enumerate.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("http_version.nasl");
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
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Send and Receive the response
req = http_get(item:"/user/index.php",  port:port);
res = http_keepalive_send_recv(port:port, data:req);

## Confirm the application
if("<TITLE>trixbox - User Mode</TITLE>" >< res)
{
  ## Try to access variables.txt file
  req = http_get(item:"/panel/variables.txt", port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  ## Check for the file status
  if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:res) &&
    ("Content-Type: text/plain" >< res) && ("Asterisk" >< res)) {
    security_message(port);
  }
}
