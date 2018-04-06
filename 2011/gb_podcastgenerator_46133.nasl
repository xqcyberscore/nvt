###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_podcastgenerator_46133.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Podcast Generator Local File Include and Cross Site Scripting Vulnerabilities
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

tag_summary = "Podcast Generator is prone to a local file-include vulnerability and a
cross-site scripting vulnerability because it fails to properly
sanitize user-supplied input.

An attacker can exploit the local file-include vulnerability using
directory-traversal strings to view and execute local files within
the context of the webserver process. Information harvested may aid
in further attacks.

The attacker may leverage the cross-site scripting issue to execute
arbitrary script code in the browser of an unsuspecting user in the
context of the affected site. This may let the attacker steal cookie-
based authentication credentials and launch other attacks.

Podcast Generator 1.3 is vulnerable; prior versions may also be
affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103062");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-02-04 13:23:33 +0100 (Fri, 04 Feb 2011)");
 script_bugtraq_id(46133);

 script_name("Podcast Generator Local File Include and Cross Site Scripting Vulnerabilities");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/46133");
 script_xref(name : "URL" , value : "http://podcastgen.sourceforge.net/download.php?lang=en");
 script_xref(name : "URL" , value : "http://www.htbridge.ch/advisory/local_file_inclusion_in_podcast_generator.html");
 script_xref(name : "URL" , value : "http://www.htbridge.ch/advisory/xss_in_podcast_generator.html");

 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("podcast_generator_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!dir = get_dir_from_kb(port:port,app:"podcast_generator"))exit(0);
url = string(dir,"/core/themes.php?L_failedopentheme=<script>alert('openvas-xss-test');</script>"); 

if(http_vuln_check(port:port, url:url,pattern:"<script>alert\('openvas-xss-test'\);</script>",check_header:TRUE)) {
     
  security_message(port:port);
  exit(0);

}

exit(0);
