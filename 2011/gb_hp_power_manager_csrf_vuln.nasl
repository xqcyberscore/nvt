##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_power_manager_csrf_vuln.nasl 7006 2017-08-25 11:51:20Z teissa $
#
# HP Power Manager Cross Site Request Forgery (CSRF) and XSS Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated the CVE-2011-0280 and related description.
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
################################i###############################################

tag_impact = "Successful exploitation could allows remote attackers to hijack
the authentication of administrators for requests that create new administrative
accounts and to execute arbitrary HTML and script code in a user's browser
session in context of an affected site

Impact Level: Application.";

tag_affected = "HP Power Manager version 4.3.2 and pror.";

tag_insight = "- The application allows users to perform certain actions via
HTTP requests without performing any validity checks to verify the requests.
- Input passed to the 'logType' parameter in 'Contents/exportlogs.asp', 'Id'
parameter in 'Contents/pagehelp.asp', 'SORTORD' parameter in
'Contents/applicationlogs.asp' and 'SORTCOL' parameter in
'Contents/applicationlogs.asp' is not properly sanitised before being";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.

A workaround is to follow instruction from the below link,
http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02711131";

tag_summary = "This host is running HP Power Manager and is prone to cross site
request forgery and cross site scripting vulnerability.";

if(description)
{
  script_id(801591);
  script_version("$Revision: 7006 $");
  script_tag(name:"last_modification", value:"$Date: 2017-08-25 13:51:20 +0200 (Fri, 25 Aug 2017) $");
  script_tag(name:"creation_date", value:"2011-02-15 08:14:35 +0100 (Tue, 15 Feb 2011)");
  script_cve_id("CVE-2011-0277", "CVE-2011-0280");
  script_bugtraq_id(46258);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("HP Power Manager Cross Site Request Forgery (CSRF) and XSS Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43058");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/46258/info");
  script_xref(name : "URL" , value : "http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02711131");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("hp_power_manager_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

## Check the Default port
port = get_http_port(default:80);

## Check the port stutus
if(!get_port_state(port)){
  exit(0);
}

## Get the version from KB if it is not available exit
if(!vers = get_kb_item(string("www/", port, "/hp_power_manager"))){
  exit(0);
}

if(!isnull(vers) && vers >!< "unknown")
{
  ## Check the version less than or equal 4.3.2
  if(version_is_less_equal(version:vers, test_version:"4.3.2")){
    security_message(port:port);
  }
}
