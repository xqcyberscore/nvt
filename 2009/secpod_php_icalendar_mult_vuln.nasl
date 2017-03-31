###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_icalendar_mult_vuln.nasl 5122 2017-01-27 12:16:00Z teissa $
#
# Multiple Vulnerabilities in PHP iCalendar
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_affected = "PHP iCalendar version 2.34 and prior on all running platform.

  Workaround:
  Restrict access to 'admin' area by adding security policies in '.htaccess'";

tag_impact = "Successful exploitation could result in Security Bypass or Directory
  Traversal attack on the affected web application.
  Impact Level: Application";
tag_insight = "- Error in admin/index.php file allows remote attackers to upload
    .ics file with arbitrary contents to the calendars/directory.
  - print.php file allows to include and execute arbitrary local files via
    a '../' in the cookie_language parameter in phpicalendar_* cookie.";
tag_solution = "No solution or patch was made available for at least one year since disclosure
  of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.
  For updates refer to http://phpicalendar.net";
tag_summary = "This host is running PHP iCalendar and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(900199);
  script_version("$Revision: 5122 $");
  script_tag(name:"last_modification", value:"$Date: 2017-01-27 13:16:00 +0100 (Fri, 27 Jan 2017) $");
  script_tag(name:"creation_date", value:"2009-01-29 15:16:47 +0100 (Thu, 29 Jan 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-5967", "CVE-2008-5968");
  script_name("Multiple Vulnerabilities in PHP iCalendar");
  desc = "

  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "
  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://milw0rm.com/exploits/6519");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/31944");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_php_icalendar_detect.nasl");
  script_require_keys("PHP/iCalendar/Ver");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!port){
  exit(0);
}

icalendarVer = get_kb_item("PHP/iCalendar/Ver");
if(!icalendarVer){
  exit(0);
}

#Check for version 2.34 and prior
if(version_is_less_equal(version:icalendarVer, test_version:"2.34"))
{
  security_message(port);
  security_message(data:string(desc, "\nPlease Ignore the warning, if"+
                           " version is greater than 2.24, as later versions\n"+
                           "are not affected by Directory Traversal attack."), port);
}
