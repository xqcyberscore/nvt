###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pligg_46998.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Pligg CMS Multiple Security Vulnerabilities
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

tag_summary = "Pligg CMS is prone to multiple security vulnerabilities because it
fails to properly sanitize user-supplied input. These vulnerabilities
include a local file-include vulnerability, a security-bypass
vulnerability, and an authentication-bypass vulnerability.

Attackers can exploit these issues to view and execute arbitrary local
files in the context of the webserver process, bypass security-
restrictions, and perform unauthorized actions.

Versions prior to Pligg CMS 1.1.4 are vulnerable.";

tag_solution = "The vendor has released a fix. Please see the references for more
information.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103139");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-04-01 13:32:12 +0200 (Fri, 01 Apr 2011)");
 script_bugtraq_id(46998);

 script_name("Pligg CMS Multiple Security Vulnerabilities");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/46998");
 script_xref(name : "URL" , value : "http://www.pligg.com/");
 script_xref(name : "URL" , value : "http://forums.pligg.com/current-version/23041-pligg-content-management-system-1-1-4-a.html");
 script_xref(name : "URL" , value : "http://h.ackack.net/the-pligg-cms-0dayset-1.html");

 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("pligg_cms_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!port){
  exit(0);
}

if(ver = get_version_from_kb(port:port,app:"pligg"))
{
  if(version_is_less(version:ver, test_version:"1.1.4")){
    security_message(port:port);
    exit(0);
  }
}

exit(0);
