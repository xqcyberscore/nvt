###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_webcalendar_mult_css_n_csrf_vuln.nasl 8447 2018-01-17 16:12:19Z teissa $
#
# WebCalendar Multiple CSS and CSRF Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation could allow attackers to conduct cross-site scripting
  and request forgery attacks.
  Impact Level: Application";
tag_affected = "WebCalendar version 1.2.0 and prior.";
tag_insight = "- Input passed to the 'tab' parameter in 'users.php' is not properly
    sanitised before being returned to the user.
  - Input appended to the URL after 'day.php', 'month.php', and 'week.php'
    is not properly sanitised before being returned to the user.
  - The application allows users to perform certain actions via HTTP requests
    without performing any validity checks to verify the requests. This can be
    exploited to delete an event, ban an IP address from posting, or change the
    administrative password if a logged-in administrative user visits a malicious
    web site.";
tag_solution = "Upgrade to WebCalendar version 1.2.1 or later
  For updates refer to http://www.k5n.us/webcalendar.php?topic=Download";
tag_summary = "The host is running WebCalendar and is prone to multiple CSS and
  CSRF Vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800472");
  script_version("$Revision: 8447 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 17:12:19 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-02-19 11:58:13 +0100 (Fri, 19 Feb 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-0636", "CVE-2010-0637", "CVE-2010-0638");
  script_bugtraq_id(38053);
  script_name("WebCalendar Multiple CSS and CSRF Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38222");
  script_xref(name : "URL" , value : "http://holisticinfosec.org/content/view/133/45/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("webcalendar_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("webcalendar/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

wcport = get_http_port(default:80);
if(!wcport){
  exit(0);
}

wcver = get_kb_item("www/" + wcport + "/webcalendar");
if(isnull(wcver)){
  exit(0);
}

wcver = eregmatch(pattern:"^(.+) under (/.*)$", string:wcver);
if(!isnull(wcver[1]))
{
  # check  WebCalendar version 1.2.0
  if(version_is_less_equal(version:wcver[1], test_version:"1.2.0")){
    security_message(wcport);
  }
}
