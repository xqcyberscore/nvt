###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jetty_cookiedump_xss_vuln.nasl 4869 2016-12-29 11:01:45Z teissa $
#
# Jetty 'CookieDump.java' Cross-Site Scripting Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  code and conduct XSS attacks via a direct GET request to cookie/.
  Impact Level: Application";
tag_affected = "Jetty version 6.1.19 and 6.1.20.";
tag_insight = "The user supplied data passed into the 'Value' parameter in the Sample
  Cookies aka 'CookieDump.java' application is not adequately sanitised
  before being returned to the user.";
tag_solution = "Upgrade to version 6.1.21 or 7.0.0 or later.
  http://jetty.mortbay.org/jetty/";
tag_summary = "This host is running Jetty WebServer and is prone to Cross-Site
  Scripting vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800954";
CPE = "cpe:/a:mortbay:jetty";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 4869 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-29 12:01:45 +0100 (Thu, 29 Dec 2016) $");
  script_tag(name:"creation_date", value:"2009-10-20 14:26:56 +0200 (Tue, 20 Oct 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-3579");
  script_name("Jetty 'CookieDump.java' Cross-Site Scripting Vulnerability");
  script_xref(name : "URL" , value : "http://www.coresecurity.com/content/jetty-persistent-xss");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/507013/100/0/threaded");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_jetty_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("Jetty/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

jettyPort =  get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!jettyPort){
  exit(0);
}

jettyVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:jettyPort);

if(!isnull(jettyVer))
{
  if(version_is_equal(version:jettyVer, test_version:"6.1.19")||
     version_is_equal(version:jettyVer, test_version:"6.1.20")){
    security_message(jettyPort);
  }
}
